import json
import logging
import os
import re
from pathlib import Path

import bcrypt
import cv2
import mysql.connector
import numpy as np
from deepface import DeepFace
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from cryptography.fernet import Fernet, InvalidToken
from starlette.middleware.sessions import SessionMiddleware

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("digital_signin")

SESSION_SECRET = os.getenv("SESSION_SECRET")
FACE_TEMPLATE_KEY = os.getenv("FACE_TEMPLATE_KEY")
if not SESSION_SECRET or not FACE_TEMPLATE_KEY:
    raise RuntimeError("Set SESSION_SECRET and FACE_TEMPLATE_KEY in the .env file.")

try:
    template_cipher = Fernet(FACE_TEMPLATE_KEY.encode("ascii"))
except (ValueError, TypeError) as error:
    raise RuntimeError("FACE_TEMPLATE_KEY must be a valid Fernet key.") from error

app = FastAPI(title="Digital Sign-In Auditor")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="strict",
    https_only=os.getenv("COOKIE_HTTPS_ONLY", "false").lower() == "true",
)

FACE_MODEL = "Facenet512"
FACE_DISTANCE_LIMIT = 0.30
MAX_IMAGE_BYTES = 3 * 1024 * 1024


def get_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", "3306")),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", ""),
            database=os.getenv("MYSQL_DATABASE", "digital_signin_auditor"),
        )
    except mysql.connector.Error as error:
        logger.exception("Could not connect to MySQL")
        raise HTTPException(status_code=503, detail="The database is unavailable.") from error


async def extract_embedding(image: UploadFile) -> np.ndarray:
    if image.content_type not in {"image/jpeg", "image/png", "image/webp"}:
        raise HTTPException(status_code=415, detail="Capture a face image using the camera.")

    image_bytes = await image.read(MAX_IMAGE_BYTES + 1)
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="The captured image is empty or too large.")

    frame = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if frame is None:
        raise HTTPException(status_code=400, detail="The captured image could not be read.")

    try:
        faces = DeepFace.represent(
            img_path=frame,
            model_name=FACE_MODEL,
            detector_backend="opencv",
            enforce_detection=True,
            align=True,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail="No clear face was detected. Face the camera in good lighting and try again.",
        ) from error

    if len(faces) != 1:
        raise HTTPException(status_code=422, detail="Ensure exactly one face is visible.")

    return np.asarray(faces[0]["embedding"], dtype=np.float32)


def encrypt_embedding(embedding: np.ndarray) -> bytes:
    return template_cipher.encrypt(json.dumps(embedding.tolist()).encode("utf-8"))


def verify_embedding(candidate: np.ndarray, encrypted_template: bytes) -> bool:
    try:
        stored = np.asarray(
            json.loads(template_cipher.decrypt(encrypted_template).decode("utf-8")),
            dtype=np.float32,
        )
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError):
        logger.exception("Stored face template could not be decrypted")
        raise HTTPException(status_code=500, detail="Stored verification data is unavailable.")

    if stored.shape != candidate.shape:
        logger.error("Stored face template does not match the configured model")
        raise HTTPException(status_code=500, detail="Stored verification data is unavailable.")

    denominator = float(np.linalg.norm(candidate) * np.linalg.norm(stored))
    if denominator == 0:
        return False

    cosine_distance = 1.0 - float(np.dot(candidate, stored) / denominator)
    return cosine_distance <= FACE_DISTANCE_LIMIT


@app.get("/")
def login_page():
    return FileResponse(BASE_DIR / "Final Year Project.html")


@app.get("/styles.css")
def stylesheet():
    return FileResponse(BASE_DIR / "styles.css", media_type="text/css")


@app.get("/admin")
def admin_page(request: Request):
    if request.session.get("role") != "administrator":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return FileResponse(BASE_DIR / "admin.html")


@app.get("/staff")
def staff_page(request: Request):
    if request.session.get("role") != "staff":
        raise HTTPException(status_code=403, detail="Staff access is required.")
    return FileResponse(BASE_DIR / "staff.html")


def require_staff(request: Request) -> int:
    if request.session.get("role") != "staff":
        raise HTTPException(status_code=403, detail="Staff access is required.")
    return int(request.session["user_id"])


@app.get("/api/staff/attendance")
def staff_attendance(request: Request):
    user_id = require_staff(request)
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, sign_in_at, sign_out_at
            FROM attendance_records
            WHERE user_id = %s
            ORDER BY sign_in_at DESC
            LIMIT 10
            """,
            (user_id,),
        )
        records = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return {
        "records": [
            {
                "id": record["id"],
                "sign_in_at": record["sign_in_at"].isoformat(),
                "sign_out_at": (
                    record["sign_out_at"].isoformat()
                    if record["sign_out_at"]
                    else None
                ),
            }
            for record in records
        ],
        "active": next(
            (
                {
                    "id": record["id"],
                    "sign_in_at": record["sign_in_at"].isoformat(),
                }
                for record in records
                if record["sign_out_at"] is None
            ),
            None,
        ),
    }


@app.post("/api/staff/attendance/sign-in")
def staff_sign_in(request: Request):
    user_id = require_staff(request)
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        cursor.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=401, detail="Your account is unavailable.")

        cursor.execute(
            """
            SELECT id FROM attendance_records
            WHERE user_id = %s AND sign_out_at IS NULL
            LIMIT 1 FOR UPDATE
            """,
            (user_id,),
        )
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="You are already signed in.")

        cursor.execute(
            "INSERT INTO attendance_records (user_id) VALUES (%s)",
            (user_id,),
        )
        connection.commit()
        return {"message": "You are signed in."}
    except HTTPException:
        connection.rollback()
        raise
    except mysql.connector.Error as error:
        connection.rollback()
        logger.exception("Could not record staff sign-in")
        raise HTTPException(status_code=503, detail="Could not record sign-in.") from error
    finally:
        cursor.close()
        connection.close()


@app.post("/api/staff/attendance/sign-out")
def staff_sign_out(request: Request):
    user_id = require_staff(request)
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        cursor.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=401, detail="Your account is unavailable.")

        cursor.execute(
            """
            SELECT id FROM attendance_records
            WHERE user_id = %s AND sign_out_at IS NULL
            ORDER BY sign_in_at DESC
            LIMIT 1 FOR UPDATE
            """,
            (user_id,),
        )
        active_record = cursor.fetchone()
        if not active_record:
            raise HTTPException(status_code=409, detail="You are not currently signed in.")

        cursor.execute(
            """
            UPDATE attendance_records
            SET sign_out_at = CURRENT_TIMESTAMP
            WHERE id = %s AND user_id = %s AND sign_out_at IS NULL
            """,
            (active_record["id"], user_id),
        )
        connection.commit()
        return {"message": "You are signed out."}
    except HTTPException:
        connection.rollback()
        raise
    except mysql.connector.Error as error:
        connection.rollback()
        logger.exception("Could not record staff sign-out")
        raise HTTPException(status_code=503, detail="Could not record sign-out.") from error
    finally:
        cursor.close()
        connection.close()


@app.get("/api/admin/users")
def admin_users(request: Request):
    if request.session.get("role") != "administrator":
        raise HTTPException(status_code=403, detail="Administrator access is required.")

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT full_name, employee_id, email, department, role, created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT 200
            """
        )
        users = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return {
        "users": [
            {
                **user,
                "created_at": user["created_at"].isoformat(),
            }
            for user in users
        ]
    }


@app.get("/api/admin/attendance")
def admin_attendance(request: Request):
    if request.session.get("role") != "administrator":
        raise HTTPException(status_code=403, detail="Administrator access is required.")

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT attendance_records.id, users.full_name, users.employee_id,
                   users.department, attendance_records.sign_in_at,
                   attendance_records.sign_out_at
            FROM attendance_records
            INNER JOIN users ON users.id = attendance_records.user_id
            ORDER BY attendance_records.sign_in_at DESC
            LIMIT 200
            """
        )
        records = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return {
        "records": [
            {
                **record,
                "sign_in_at": record["sign_in_at"].isoformat(),
                "sign_out_at": (
                    record["sign_out_at"].isoformat()
                    if record["sign_out_at"]
                    else None
                ),
            }
            for record in records
        ]
    }


@app.post("/api/signup")
async def signup(
    request: Request,
    full_name: str = Form(...),
    employee_id: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    department: str = Form(...),
    biometric_consent: str = Form(...),
    face_image: UploadFile = File(...),
):
    if biometric_consent != "yes":
        raise HTTPException(status_code=400, detail="Consent is required to enroll facial verification.")
    full_name = full_name.strip()
    employee_id = employee_id.strip()
    email = email.strip().lower()
    department = department.strip()
    password_bytes = password.encode("utf-8")
    if not full_name or len(full_name) > 150:
        raise HTTPException(status_code=400, detail="Enter a name of 1 to 150 characters.")
    if not employee_id or len(employee_id) > 60:
        raise HTTPException(status_code=400, detail="Enter an employee ID of 1 to 60 characters.")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if not department or len(department) > 120:
        raise HTTPException(status_code=400, detail="Enter a department of 1 to 120 characters.")
    if len(password_bytes) < 10 or len(password_bytes) > 72:
        raise HTTPException(status_code=400, detail="Password must be 10 to 72 bytes.")

    embedding = await extract_embedding(face_image)
    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    encrypted_template = encrypt_embedding(embedding)
    connection = get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users
                (full_name, employee_id, email, password_hash, department, role,
                 face_model, face_template, biometric_consent_at)
            VALUES (%s, %s, %s, %s, %s, 'staff', %s, %s, CURRENT_TIMESTAMP)
            """,
            (
                full_name,
                employee_id,
                email,
                password_hash,
                department,
                FACE_MODEL,
                encrypted_template,
            ),
        )
        connection.commit()
    except mysql.connector.IntegrityError as error:
        connection.rollback()
        raise HTTPException(
            status_code=409,
            detail="That email or employee ID is already registered.",
        ) from error
    finally:
        cursor.close()
        connection.close()

    request.session.clear()
    return {"message": "Account created. You can now sign in with facial verification."}


@app.post("/api/login")
async def login(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    face_image: UploadFile = File(...),
):
    if role not in {"staff", "administrator"}:
        raise HTTPException(status_code=400, detail="Select a valid account type.")
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password is too long.")

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, full_name, password_hash, role, face_model, face_template
            FROM users
            WHERE (email = %s OR employee_id = %s) AND role = %s
            LIMIT 1
            """,
            (identifier.strip().lower(), identifier.strip(), role),
        )
        user = cursor.fetchone()
    finally:
        cursor.close()
        connection.close()

    if not user or not bcrypt.checkpw(password.encode("utf-8"), bytes(user["password_hash"])):
        raise HTTPException(status_code=401, detail="The login details could not be verified.")
    if user["face_model"] != FACE_MODEL:
        raise HTTPException(status_code=409, detail="Face verification setup needs to be updated.")

    candidate = await extract_embedding(face_image)
    if not verify_embedding(candidate, bytes(user["face_template"])):
        raise HTTPException(status_code=401, detail="The login details could not be verified.")

    request.session.clear()
    request.session["user_id"] = user["id"]
    request.session["full_name"] = user["full_name"]
    request.session["role"] = user["role"]
    return {"message": "Identity verified.", "role": user["role"], "name": user["full_name"]}


@app.get("/api/me")
def current_user(request: Request):
    if "user_id" not in request.session:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return {
        "name": request.session["full_name"],
        "role": request.session["role"],
    }


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "You have been signed out."}
