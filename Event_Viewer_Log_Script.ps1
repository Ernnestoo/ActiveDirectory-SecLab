# Enable auditing successful and failed logons
auditpol /set /subcategory:"Logon" /success:enable /failure:enable 

# Enable auditing for account lockouts 
auditpol /set /subcategory"Account Lockout" /success:enable /failure:enable 

# Viewed all the activated audit policies in the "Logon/off" category 
auditpol /get /subcategory:"Logon"

# Viewed all activated audit policies across all categories 
auditpol /get /category:*

# Saved audit policy config to a file 
auditpol /get /category:* > config_audit_policies.txt

