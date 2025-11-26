CREATE OR REPLACE TRIGGER trg_check_suspicious_login
AFTER INSERT ON login_audit
FOR EACH ROW
DECLARE
    PRAGMA AUTONOMOUS_TRANSACTION; 
    v_fail_count NUMBER;
BEGIN
    IF :NEW.status = 'FAILED' THEN
        -- Count existing committed failures for today
        SELECT COUNT(*) INTO v_fail_count
        FROM login_audit
        WHERE username = :NEW.username 
          AND status = 'FAILED'
          AND TRUNC(attempt_time) = TRUNC(SYSDATE);
          
        -- If failures + current one > 2, trigger alert
        IF (v_fail_count + 1) > 2 THEN
            INSERT INTO security_alerts 
            (username, failed_attempts, alert_message, notification_contact)
            VALUES 
            (:NEW.username, (v_fail_count + 1), 'Suspicious activity: Multiple failed login attempts.', 'admin@security.org');
            COMMIT;
        END IF;
    END IF;
    COMMIT;
END;
/
