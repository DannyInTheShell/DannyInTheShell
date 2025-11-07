# Incident Report Analysis - NIST CSF

## Summary  
The organization recently experienced a security incident where an ICMP flood attack disrupted internal network services. The attack caused a temporary outage, preventing normal traffic from accessing network resources. Our incident management team responded by blocking the incoming flood, stopping all non-critical network services, and restoring critical network services. Moving forward, security enhancements have been implemented to prevent similar attacks, including improved firewall rules, IDS/IPS deployment, and enhanced monitoring.  

## Identify  
It was found that a malicious actor targeted the organization by sending a flood of ICMP pings into the company's network through an unconfigured firewall. This vulnerability allowed the malicious actor to overwhelm the company's network through a DDoS/ICMP Flood attack, which disrupted the organization’s internal network services. Normal internal network traffic was unable to access network resources. The effects were sudden and lasted for two hours until the incoming ICMP packets were blocked and critical services restored. The firewall’s misconfiguration resulted from outdated security policies that did not restrict ICMP traffic. Moving forward, regular firewall audits and policy enforcement will be conducted to prevent similar vulnerabilities.  

## Protect  
To address this security incident, the network security team implemented:  

- A new firewall rule to limit the rate of incoming ICMP packets  
- Source IP address verification on the firewall to check for spoofed IP addresses on incoming ICMP packets  
  - Firewall rules will be reviewed and updated every quarter to ensure compliance with security policies, and all firewall logs will be monitored using SIEM alerts  
- Network monitoring software to detect abnormal traffic patterns  
- An IDS/IPS to filter out ICMP traffic based on suspicious characteristics  

## Detect  
To detect incoming external ICMP packets from non-trusted IP addresses attempting to pass through the organization’s network firewall, the team will implement a combination of firewall logging tools and IDS/IPS. These tools will monitor all incoming traffic from the internet, analyze patterns, and filter suspicious ICMP packets in real-time.  

Additionally, a SIEM solution will be integrated to further improve the organization’s security posture by collecting, analyzing, and monitoring log data from firewalls, network devices, and other critical systems. It will be configured to monitor critical activities, detect anomalies, and send automated alerts to the incident response team when necessary. SIEM alerts will be monitored by the SOC, with predefined escalation protocols based on threat severity. Regular tuning of SIEM rules will be conducted to reduce false positives and ensure relevant threat detection. This proactive approach will strengthen the organization’s ability to detect and respond to suspicious activities or traffic on the network effectively.  

## Respond  
By implementing IDS, IPS, and SIEM tools, the cybersecurity team will receive real-time alerts of any suspicious ICMP packets. This will significantly improve the response and mitigation time, reducing it from the two-hour delay experienced during this incident.  

If an ICMP incident is detected, the incident management team will take the following actions:  

1. **Investigate and Analyze:**  
   - Review the alert to confirm whether the activity constitutes an active attack.  
   - Analyze network traffic to determine the source, scope, and attack type.  

2. **Mitigation Actions:**  
   - Use firewall, router, IDS, or IPS rules to temporarily block all ICMP traffic and permanently block identified malicious IP addresses.  
   - If necessary, temporarily disable ICMP on affected systems or network segments to mitigate further risk.  
   - Identify and isolate any affected systems to prevent further impact.  

3. **Containment & Business Continuity:**  
   - If the attack is severe, temporarily shut down non-critical network services to free up bandwidth and prioritize critical system availability.  
   - Ensure firewalls, IDS, and IPS signatures are updated to prevent further ICMP-based attacks.  

4. **Monitoring and Evidence Collection:**  
   - Continue to monitor network activity for signs of persistent threats.  
   - Collect and preserve log evidence for forensic analysis and possible legal action.  

5. **Communication & Documentation:**  
   - Inform upper management of the attack and response actions.  
   - Management will coordinate communication with key stakeholders, including IT, senior leadership, and potentially affected departments.  
   - Document the incident for post-incident review and future prevention strategies.  

6. **Training & Preparedness:**  
   - All upper management and security personnel will be trained on this ICMP attack response plan to ensure a coordinated and efficient response in future incidents.  
   - Incident response training will be conducted semi-annually to ensure all security personnel remain prepared for similar threats.  

## Recover  
Once it has been confirmed that the attack has been mitigated, the following recovery actions will be taken:  

1. **Restore Critical Services First**  
   - The priority after mitigating an attack is to restore business-critical systems as soon as possible. This ensures minimal operational disruption.  
     - Ensure firewalls and ACLs block future ICMP floods before restoring systems (to avoid reinfection).  
     - Bring critical network services back online first, then verify stability.  

2. **Gradually Reintroduce Non-Critical Services**  
   - To avoid overwhelming the network or exposing non-critical systems to residual threats.  
     - Once it's confirmed that the ICMP flood has timed out, bring non-essential services back online in phases while monitoring for anomalies.  
     - Remove temporary countermeasures after confirming security.  

3. **Conduct a Post-Incident Review**  
   - This ensures the organization understands how the attack happened and what can be improved before finalizing the response.  
     - Analyze logs, IDS/IPS data, firewall configurations, and attack patterns to identify security gaps.  
     - Assess whether detection and response mechanisms worked as expected.  
     - A formal post-incident report will be delivered to senior management within 48 hours after full recovery.  

4. **Update the Incident Response Plan (IRP)**  
   - Lessons learned need to be documented and integrated into future cybersecurity protocols.  
     - Modify policies, playbooks, and security configurations based on findings.  

5. **Provide Additional Training for IT & Security Teams**  
   - Ensure that personnel better recognize and respond to similar attacks in the future.  
     - Train IT staff on improved monitoring, detection, and response techniques for ICMP-based attacks.  
