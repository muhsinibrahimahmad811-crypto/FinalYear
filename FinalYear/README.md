# Digital Sign-In Auditor

## Local setup

1. Install Python and MySQL Server.
2. Create and activate a virtual environment, then install dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Create the database and tables:

   ```powershell
   Get-Content .\schema.sql | mysql -u root -p
   ```

   Then create a dedicated MySQL account for the app:

   ```sql
   CREATE USER 'digital_signin_app'@'localhost' IDENTIFIED BY 'use-a-unique-password';
   GRANT SELECT, INSERT ON digital_signin_auditor.* TO 'digital_signin_app'@'localhost';
   GRANT UPDATE ON digital_signin_auditor.attendance_records TO 'digital_signin_app'@'localhost';
   ```

   Use that account in `.env`, not the MySQL root account.

4. Copy `.env.example` to `.env`. Set the MySQL password and generate secrets:

   ```powershell
   py -c "import secrets; print(secrets.token_urlsafe(48))"
   py -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Put the first value in `SESSION_SECRET` and the second in `FACE_TEMPLATE_KEY`.
   Keep `.env` and the face-template key private. Losing the key prevents stored
   templates from being verified.

5. Start the local server:

   ```powershell
   uvicorn app:app --reload
   ```

6. Open `http://127.0.0.1:8000`. DeepFace downloads its model weights the first
   time it is used; after setup, camera frames are processed by the local server.

The schema creates the staff attendance table. If the database was created
before attendance tracking was added, rerun the schema command to create it.
Staff login opens `/staff`, where users can sign in once and sign out once per
active session. Their personal page lists the ten most recent records. The
server session determines the user; clients cannot choose or submit another
user's ID.

## Face-data handling and limitations

Signup and login require camera permission and explicit consent. The server
processes each captured frame in memory and stores only an encrypted face
template, never the original camera image. Public signup creates staff accounts
only. Create administrator accounts through a separately protected admin
provisioning process; do not make administrator access self-service. To set up
the first administrator for a local demonstration:

```sql
UPDATE digital_signin_auditor.users
SET role = 'administrator'
WHERE email = 'admin@example.gov';
```

First register that person through Sign Up, then run the update using a
privileged MySQL connection. The app's MySQL account intentionally has no
permission to change roles. On the login page select **Administrator** and use
that account's ID/email, password, and enrolled face. Successful verification
opens `/admin`; the protected dashboard lists accounts and the 200 most recent
attendance records.

Staff accounts are sent to `/staff` after verified login. They can sign in,
sign out, and view their ten latest attendance records. Attendance actions are
restricted to the authenticated staff member and duplicate active sessions are
rejected.

This is a student-project prototype, not a production biometric system. Face
matching alone does not provide liveness detection and can be vulnerable to
photo/video spoofing. The similarity threshold must be evaluated with real
lighting and camera conditions before any operational use. Use HTTPS, access
controls, backups for the encryption key, and a clear retention/deletion policy
before deployment.
