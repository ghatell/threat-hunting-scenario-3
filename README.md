## **Data Exfiltration from PIP'd Employee** 

![ChatGPT Image Apr 5, 2025 at 05_11_23 PM](https://github.com/user-attachments/assets/4e02a44b-5802-4618-9142-2a210bf11f69)


## 📚 **Scenario:**  
An employee named John Doe, working in a sensitive department, was recently placed on a performance improvement plan (PIP). After displaying concerning behavior, management suspects John may be planning to steal proprietary information and leave the company. The investigation involves analyzing activities on John’s corporate device (`sa-mde-test-2`) using Microsoft Defender for Endpoint (MDE).  

---

## 📊 **Incident Summary and Findings**  

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:** Frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  
     ```kql
     DeviceFileEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceNetworkEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceProcessEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceFileEvents
     | where DeviceName == "sa-mde-test-2"
     | where FileName endswith ".zip"
     | order by Timestamp desc
     ```

<img width="1249" alt="log1" src="https://github.com/user-attachments/assets/c8fd8489-25ef-4fa1-8c43-b7419bc0509c" />

___
     
2. **⚙️ Process Analysis:**  
   - **Observed Behavior:** I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 mintutes after. I discoverd around the same time. A powershell script silently installed 7zip and then used 7zip to zip up employee data into an archive.
   - **Detection Query (KQL):**  

     ```kql
     let VMName = "sa-mde-test-2";
     let specificTime = datetime(2025-04-02T12:50:01.6274019Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```
     
<img width="1245" alt="log2" src="https://github.com/user-attachments/assets/fec2c74e-2ddb-4825-9388-4d6b41c27483" />

___

3. **🌐 Network Exfiltration Check:**  
   - **Observed Behavior:** No evidence of data exfiltration via network logs during the time frame.  

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "sa-mde-test-2";
     let specificTime = datetime(2025-04-02T12:50:01.6274019Z);
     DeviceNetworkEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```
     
<img width="1269" alt="log3" src="https://github.com/user-attachments/assets/2f68b6af-5c4b-4a15-b666-a61bce949913" />
     
___     

4. **📝 Response:**  

   - I relayed the information to the employees manager including everything with the archives being created at regular intervals via PowerShell script. There didn’t appear to be any evidence of exfiltration. Standing by for further instructions from management.

---

---

## 🛡️ **MITRE ATT&CK Framework TTPs**  

| **Tactic**           | **Technique**                                                                                     | **ID**            | **Description**                                                                                                                                                 |  
|-----------------------|---------------------------------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| 🛠️ **Execution**      | PowerShell                                                                                       | T1059.001         | PowerShell scripts were used to silently install 7-Zip and execute file compression commands.                                                                   |  
| 📦 **Collection**      | Archive Collected Data                                                                           | T1560.001         | Employee data was compressed into `.zip` files using 7-Zip, possibly for easier handling or exfiltration.                                                       |  
| 📂 **Exfiltration**    | Exfiltration Over Alternative Protocol                                                           | T1048             | Although no network exfiltration was detected, the technique aligns with the potential misuse of alternate protocols for stealthy data transfer.                |  
| 🔍 **Discovery**       | Process Discovery                                                                                | T1057             | Processes were reviewed to identify activities surrounding the installation and use of 7-Zip for archiving.                                                     |  

---

### 🧑‍💻 **Next Steps**  
1. Monitor John’s account activity for unusual access or privilege escalation.  
2. Implement DLP (Data Loss Prevention) measures to alert on potential data exfiltration.  
3. Escalate findings to management and recommend a follow-up review of John's device for additional forensic artifacts.  

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: Soroush Asadi
- **Author Contact**: [Linkedin](https://www.linkedin.com/in/soroush-asadi-881098178/)
- **Date**: April 5, 2025

## Validated By:
- **Reviewer Name**: Josh Madakor
- **Reviewer Contact**: [Linkedin](https://www.linkedin.com/in/joshmadakor/)
- **Validation Date**: April, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 5, 2025`  | `Soroush Asadi`   
