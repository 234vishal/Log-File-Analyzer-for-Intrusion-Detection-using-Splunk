# Log-File-Analyzer-for-Intrusion-Detection-using-Splunk
The project helps beginners understand basic log analysis, pattern detection, and visualization in Splunk without needing a live environment.
This project demonstrates how to detect suspicious activities like brute-force attempts, port scanning, and DoS patterns using Splunk.
I ingested sample Apache and SSH logs into Splunk, created searches to identify attack patterns, visualized access trends by IP and time, and cross-referenced log data with a public IP blacklist to flag malicious hosts.

# Objective

- [`Install Splunk`](##-Install-Splunk)</br>
- Parse and analyze web (Apache) and SSH logs
- [Detect brute-force, scanning, and DoS attempts](##-Detect-Brute-force,-Scanning,-and-DoS-Attempts )</br>
- Visualize traffic patterns by IP and time
- Match IPs against blacklist data
- Generate simple event dashboards


## Install Splunk
1. Go to [`Splunk Free Download`](https://www.splunk.com/en_us/download/splunk-enterprise.html) and download `Splunk Enterprise` (free trial).
2. Install and start Splunk → it will run on [`http://localhost:8000`](http://localhost:8000)
3. Create an admin user when it asks.

## Parse and analyze web (Apache) and SSH logs
For this project, I have used a sample SSH log file downloaded from GitHub to simulate real-world SSH connection events. The log includes fields such as `auth_attempts`, `auth_success`, `id.orig_h`, `id.resp_h, and event_type, which helped identify patterns like successful and failed logins. This dataset was ingested into Splunk for further analyaysis. 

* **Screenshots:**
     - **Sample Log1:**
       <img width="1920" height="881" alt="accesslog" src="https://github.com/user-attachments/assets/16eb23b4-251b-4d30-b74f-ec7e3fe539fe" />

     - **Sample Log2:**
       <img width="1889" height="888" alt="sshlog" src="https://github.com/user-attachments/assets/9d653d8a-a97c-477f-8479-52575da3a4cf" />

  **Download Sample Logs From Here:**
   - Download sample Log1: [access1.log](https://github.com/user-attachments/files/22965926/access1.log)
   - Download sample Log2: [Sample_SSH.log](https://github.com/user-attachments/files/22965943/Sample_SSH.log)

### Table View For SSH Event Logs
This SPL command is Used to format the log in a table form:

   ````
SPL
index=main sourcetype=ssh
| table _time, id.orig_h, id.orig_p, id.resp_h, id.resp_p, auth_attempts, auth_success, event_type, proto

   ````
- **Explanation of columns:**

    -  `_time` → Timestamp of the event
    - `id.orig_h` → Source IP (attacker/client)
    - `id.orig_p` → Source port
    - `id.resp_h` → Destination IP (server)
    - `id.resp_p` → Destination port (usually 22 for SSH)
    - `auth_attempts` → Number of login attempts in this session
    - `auth_success` → Whether login was successful (true/false)
    - `event_type` → Event description (e.g., "Successful SSH Login")
    - `proto` → Protocol (TCP/UDP)
 
- **Screenshot:**
     <img width="1909" height="887" alt="event logs" src="https://github.com/user-attachments/assets/813a257e-ff1b-4109-8082-c0f62cf4bdb5" />


  
## Detect Brute-force, Scanning, and DoS Attempts 
In this phase, we focus on identifying potential security threats such as brute-force attacks, network scanning activities, and denial-of-service (DoS) attempts by analyzing the log data using Splunk Processing Language (SPL) queries. By applying different search filters and statistical commands, we can uncover abnormal behavior patterns like repeated login failures, high-frequency connection requests, and unusual traffic spikes. This analysis helps in recognizing suspicious activities hidden within large volumes of log data and provides actionable insights to strengthen system security and monitoring.

### Detecting Brute-Force Attempt:
This SPL command is used to detect possible brute-force attacks by finding IP addresses (id.orig_h) with multiple failed authentication attempts. It counts the number of failed logins, filters those with 5 or more failures, and sorts them in descending order to highlight the most suspicious sources.

  ```
  SPL
  index=main sourcetype=ssh (auth_success=false OR auth_success="0" OR auth_success="False") | stats sum(auth_attempts) AS failed_attempts, count AS events BY id.orig_h | where failed_attempts >= 5 | sort - failed_attempts
  
  ```

- **Explanation:**
     - Finds events that show failed SSH auths `(auth_success=false)`,
     - Sums the auth_attempts per source IP `(id.orig_h)`,
     - Shows source IPs with `failed_attempts >= 5`, and sorts by the worst offenders.

- **Screenshot:**
    <img width="1920" height="878" alt="Faild logins" src="https://github.com/user-attachments/assets/c04cf56e-6967-414f-8f48-f8e3ec9aee9c" />


### Detecting port scanning activity:
This SPL command is used to detect port scanning activity by identifying source IPs (id.orig_h) that have connected to more than 10 different destination ports. It counts the distinct ports scanned and lists the IPs most likely performing reconnaissance.

  ```
SPL
index="main" sourcetype="ssh" | stats dc(id.resp_p) AS ports_scanned BY id.orig_h | where ports_scanned > 10

  ```

* **Explanation:**

   - `id.orig_h` = Source IP (attacker)

   - `dc(id.resp_p)` = Counts how many different destination ports it tried to reach

   - Shows IPs that tried more than 10 ports — common in port scanning (you can increase and decrease the number)

- **Screenshot:**
  <img width="1920" height="1019" alt="scanning" src="https://github.com/user-attachments/assets/a7291f9e-4676-4455-9ff2-8c925f7a1a5b" />


### Detecting Possible DoS Attack:

This SPL command is used to detect possible DoS (Denial-of-Service) attacks by identifying IPs `(id.orig_h)` that send more than 30 requests within a single second. It helps pinpoint sources generating unusually high traffic in a short time frame.

  ```
SPL
index="main" sourcetype="ssh" | bin _time span=1s | stats count AS requests BY id.orig_h, _time | where requests > 30
  ```
* **Explanation:**

   - Groups logs per second (`span=1sec`)
   - Counts how many requests each IP made
   - Shows IPs making more than 30 requests in a second — possible DoS
 
* **Screenshot:**
  <img width="1920" height="765" alt="dos" src="https://github.com/user-attachments/assets/2a5796f8-7149-4af2-bfdf-9f157218b371" />

## Visualize Traffic Patterns by IP and Time
This SPL command is used to visualize access patterns over time by creating a time chart that shows the number of events generated by each source IP (`id.orig_h`). It helps in spotting unusual activity trends or traffic spikes.

  ```
SPL

index="main"| timechart count BY id.orig_h
  ```

* **Explanation:**

  - timechart creates a timeline graph.
  - count BY `id.orig_h` shows how many events came from each source IP over time.
  - This will automatically give you a line chart showing which IPs are most active and when.

* **Screnshot:**
  <img width="1920" height="665" alt="visualize" src="https://github.com/user-attachments/assets/56d28e1f-5b0c-42cd-885b-9590ff14a961" />


## Matching IPs Against Blacklist Data

* **Create a small blacklist file:** Open Notepad and type a few known malicious IPs and save it as `blacklistIP.csv` on your desktop.
   
```
ip
10.0.0.14
10.0.0.18
10.0.0.21
10.0.0.25
10.0.0.44
```

* **Upload the blacklist into Splunk:**
   - Go to `Settings` → `Lookups` → `Lookup table files` → `Add new`
   - Upload your blacklistIP.csv
   - Give it a name like blacklist_ip.csv
- **Screenshot:**
  <img width="1920" height="814" alt="csv" src="https://github.com/user-attachments/assets/377a4c82-dd57-4dda-abfe-2a525470c70e" />

* **Command:**
This SPL command is used to identify malicious IPs by comparing log data with a public IP blacklist. It matches the source IPs (`id.orig_h`) from the logs against the blacklist file (`ip_blacklistIP.csv`) and displays only those that are found to be suspicious, along with the number of events linked to each bad IP.

    ```
    index="main"
    | lookup ip_blacklistIP.csv ip AS id.orig_h OUTPUT ip AS bad_ip
    | where isnotnull(bad_ip)
    | stats count by id.orig_h, bad_ip
    ```

* **Explanation:**
Shows how many events matched your blacklist and from which IP.

- **Screenshot:**
  <img width="1920" height="734" alt="badip" src="https://github.com/user-attachments/assets/2370eddb-cb75-47dc-8e68-269b53c78db1" />


## GenerateD Simple Event Dashboards

The Intrusion Detection Dashboard provides a clear visual summary of all analyzed security events. It displays key insights such as brute-force attempts, port scanning activity, possible DoS attacks, access trends over time, and detected blacklisted IPs. Each panel represents a specific detection use case, making it easy to monitor suspicious patterns and identify potential threats at a glance. This dashboard helps visualize log data in an organized and beginner-friendly way, turning raw security events into actionable insights.

* **Screenshots:**
  <img width="861" height="795" alt="dash1" src="https://github.com/user-attachments/assets/f8d1212d-f32f-444e-993a-753cf9c6793a" />

  <img width="1031" height="822" alt="dash2" src="https://github.com/user-attachments/assets/5b22f5fa-43fb-40d3-8f6c-49e8d25d779b" />


## Conclusion

This project demonstrates how Splunk can be effectively used to detect and visualize potential security threats from log data. By analyzing SSH and Apache logs, identifying abnormal patterns, and correlating with blacklisted IPs, it showcases the fundamental steps of intrusion detection. The dashboard provides a clear, real-time view of network activities, making it easier to recognize and respond to suspicious behavior. Overall, this project serves as a practical foundation for beginners to understand log-based threat detection and security monitoring using Splunk.
 

  




  

 

















