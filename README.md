📚 What This Project Is About

This project is all about exploring real-world security scenarios involving Active Directory (AD). We’re simulating both offensive attacks like social engineering and AD exploitation, and defensive responses like monitoring and incident response. It’s a hands-on way to learn how attacks happen and how defenders can respond in real time.

🎯 What We’re Trying to Do
	•	Launch realistic AD attacks using common pentesting tools.
	•	Run social engineering campaigns like phishing emails and fake payloads.
	•	Secure and harden the AD environment by fixing vulnerabilities.
	•	Create useful scripts for attacking and defending.

🛠️ Tools We’re Using

For Attacking:
	•	Kali Linux: Main attack platform.
	•	GoPhish: For sending phishing emails.
	•	BloodHound & Mimikatz: For AD privilege escalation and finding weak spots.
	•	PowerShell Empire: For running post-exploitation commands.

For Defending:
	•	Windows Event Viewer & Sysmon: For log monitoring and tracking attacker moves.
	•	Microsoft Defender: Built-in endpoint protection.
	•	Custom PowerShell Scripts: For automating incident responses and security checks.

⚙️ How We Set Up the Lab
	1.	Virtual Machines:
	•	Windows 11 VM (Defender)
	•	Kali Linux VM (Attacker)
	2.	Network Configuration:
	•	Host-Only Network for secure communication.
	•	Static IPs for reliable testing.
	3.	Active Directory Setup:
	•	Built a sample AD environment with intentional misconfigurations to test against.
	•	Added a few “users” with different access levels for testing privilege escalation.

📋 How We Run the Project
	1.	Preparation Phase:
	•	Set up the environment.
	•	Install and configure tools like BloodHound, GoPhish, and Sysmon.
	2.	Attack Phase:
	•	Start phishing campaigns, AD attacks, and privilege escalation attempts.
	•	Keep track of what works and what doesn’t.
	3.	Defense Phase:
	•	Monitor system logs for any unusual activity.
	•	Apply security fixes like disabling old accounts and enforcing password policies.
	4.	Debriefing Phase:
	•	Discuss what happened: where the attacks succeeded or failed, and how defenses held up.
	•	Take screenshots, make notes, and compile reports.

📊 What We’ll Deliver
	•	Attack Report: What attacks we tried, what tools we used, and how far we got.
	•	Defense Report: What defenses were put in place and how effective they were.
	•	Lessons Learned: What we improved and what we’ll do differently next time.

🚨 Important Note

   This project is for learning and educational purposes only. The techniques we’re using are designed for ethical hacking and cybersecurity training. Never use these methods in real-world environments without permission!
	
