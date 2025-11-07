# **PCI DSS and GDPR Readiness Audit for Botium Toys** 

This scenario is based on a fictional company:  

Botium Toys is a small U.S. business that develops and sells toys. The company operates from a single physical location that functions as their main office, a storefront, and a warehouse for their products. Over time, Botium Toys’ online presence has grown, attracting customers in the U.S. and internationally. This expansion has increased the pressure on their Information Technology (IT) department to support a global online market.  

The IT department manager has decided to conduct an internal IT audit to address growing concerns. The focuse is on maintaining compliance and ensuring the company can sustain business operations as it scales, despite lacking a clear plan. The internal audit aims to secure the company’s infrastructure, identify and mitigate potential risks, threats, and vulnerabilities to critical assets, and ensure compliance with regulations. 

Particular attention is being paid to regulations regarding:  
- Internally processing and accepting online payments.  
- Conducting business in the European Union (E.U.).  

To address these challenges, the **National Institute of Standards and Technology Cybersecurity Framework (NIST CSF)** has been implemented and the following steps have been taken:  
1. **Defined Audit Scope and Goals:** Established clear objectives for the internal audit.  
2. **Listed Managed Assets:** Documented assets currently overseen by the IT department.  
3. **Completed a Risk Assessment:** Evaluated risks and potential vulnerabilities in the current security posture.  

### Objective of the Audit  
The primary goal is to provide an overview of the risks and potential fines the company may face due to its current security posture.  

The results of this audit will help Botium Toys strengthen their security posture and ensure compliance with applicable regulations as the company continues to grow.  

--------------------------------------------------------------

# **Botium Toys: Scope, Goals, and Risk Assessment Report**

## **Scope and Goals of the Audit**

### **Scope**
The scope is defined as the entire security program at Botium Toys. This means all assets need to be assessed alongside internal processes and procedures related to the implementation of controls and compliance best practices.

### **Goals**
Assess existing assets and complete the controls and compliance checklist to determine which controls and compliance best practices need to be implemented to improve Botium Toys’ security posture.


## **Current Assets**
Assets managed by the IT Department include: 
- **On-premises equipment** for in-office business needs.  
- **Employee equipment**: end-user devices (desktops/laptops, smartphones), remote workstations, headsets, cables, keyboards, mice, docking stations, surveillance cameras, etc.
- **Storefront products** available for retail sale on-site and online; stored in the company’s adjoining warehouse.
- **Management of systems, software, and services**: accounting, telecommunication, database, security, e-commerce, and inventory management.
- **Internet access**.
- **Internal network**.
- **Data retention and storage**.
- **Legacy system maintenance**: end-of-life systems that require human monitoring.


## **Risk Assessment**

### **Risk Description**
Currently, there is inadequate management of assets. Additionally, Botium Toys does not have all of the proper controls in place and may not be fully compliant with U.S. and international regulations and standards. 

### **Control Best Practices**
The first of the five functions of the **NIST Cybersecurity Framework (CSF)** is *Identify*. Botium Toys will need to:
- Dedicate resources to identify assets for appropriate management.
- Classify existing assets and determine the impact of their loss on business continuity.

### **Risk Score**
On a scale of 1 to 10, the risk score is **8**, which is fairly high due to a lack of controls and adherence to compliance best practices.


## **Additional Comments**
The potential impact from the loss of an asset is rated as **medium**, because the IT department does not know which assets would be at risk. The risk to assets or fines from governing bodies is rated as **high** because Botium Toys does not have all necessary controls in place or fully adhere to compliance regulations to keep critical data private and secure. Below are specific details:

### **Identified Issues:**
- **Employee access**: All employees currently have access to internally stored data, including cardholder data and customers' PII/SPII.
- **Encryption**: Customers' credit card information is not encrypted during acceptance, processing, transmission, or storage.
- **Access controls**: Least privilege and separation of duties have not been implemented.
- **Data integrity and availability**: The IT department has ensured data integrity and implemented controls for availability.
- **Firewall**: A firewall is in place, blocking traffic based on defined security rules.
- **Antivirus software**: Installed and monitored regularly by the IT department.
- **Lack of IDS**: No intrusion detection system (IDS) is installed.
- **Disaster recovery**: No disaster recovery plans or backups of critical data exist.
- **E.U. compliance**: A plan to notify E.U. customers within 72 hours of a breach is in place, and privacy policies are enforced internally.
- **Password policy**:
  - Requirements are nominal and not aligned with current best practices (e.g., minimum length, complexity).
  - No centralized password management system is in place, leading to productivity issues with password recovery.
- **Legacy systems**: Monitored and maintained, but there is no regular schedule or clear intervention methods.
- **Physical security**: The physical location has sufficient locks, up-to-date CCTV surveillance, and functioning fire detection/prevention systems.

------------------------------------------------------------------

# Botium Controls and Compliance Checklist

## Controls Assessment Checklist

| Yes | No | Control | Explanation |
| --- | --- | ------- | ----------- |
|  | ● | Least Privilege | Currently, all employees have access to customer data. Access privileges should be restricted to minimize the risk of a breach. |
|  | ● | Disaster recovery plans | Disaster recovery plans are not currently in place and must be implemented to ensure business continuity. |
|  | ● | Password policies | Employee password requirements are insufficient, which could make it easier for a threat actor to gain access to secure data and other assets through employee work equipment or the internal network. |
|  | ● | Separation of duties | It should be implemented to minimize the risk of fraud and unauthorized access to critical data. |
| ● |  | Firewall | The current firewall filters traffic according to a well-defined set of security rules. |
|  | ● | Intrusion detection system (IDS) | The IT department should implement an IDS to detect potential intrusions by threat actors. |
|  | ● | Backups | The IT department should implement backups for critical data to ensure business continuity in the event of a breach. |
| ● |  | Antivirus software | The IT department has installed antivirus software and monitors it regularly.|
|  | ● | Manual monitoring, maintenance, and intervention for legacy systems | The asset list identifies the use of legacy systems. While these systems are monitored and maintained, the risk assessment reveals that there is no regular schedule for these tasks, and the procedures and policies for intervention are unclear. This could leave these systems vulnerable to a breach. |
|  | ● | Encryption | Encryption is not currently in use; implementing it would enhance the confidentiality of sensitive information.|
|  | ● | Password management system | A password management system is not currently in place. Implementing this control would enhance productivity for the IT department and other employees when addressing password-related issues.|
| ● |  | Locks (offices, storefront, warehouse) | The store’s physical location, main offices, store front, and warehouse of products, has sufficient locks. |
| ● |  | Closed-circuit television (CCTV) surveillance | CCTV is installed/functioning at the store’s physical location. |
| ● |  | Fire detection/prevention (fire alarm, sprinkler system, etc.) | Physical location has a functioning fire detection and prevention system. |


## Compliance Checklist

### Payment Card Industry Data Security Standard (PCI DSS)

| Yes | No | Best Practice | Explanation |
| --- | --- | ------------- | ----------- |
|  | ● | Only authorized users have access to customers’ credit card information. | At present, all employees have access to the company’s internal data. |
|  | ● | Credit card information is accepted, processed, transmitted, and stored internally, in a secure environment. | Credit card information is not encrypted, and all employees currently have access to internal data, which includes customers' credit card details. |
|  | ● | Implement data encryption procedures to better secure credit card transaction touchpoints and data. | The company currently does not use encryption. |
|  | ● | Adopt secure password management policies. | Password policies are minimal, and there is currently no password management system in place.|

### General Data Protection Regulation (GDPR)

| Yes | No | Best Practice | Explanation |
| --- | --- | ------------- | ----------- |
|  | ● | E.U. customers’ data is kept private/secured. | The company currently does not use encryption. |
| ● |  | There is a plan in place to notify E.U. customers within 72 hours if their data is compromised/there is a breach. | A plan is in place to notify E.U. customers within 72 hours of a data breach. |
|  | ● | Ensure data is properly classified and inventoried. | The current assets have been inventoried and listed, but they have not been classified. |
| ● |  | Enforce privacy policies, procedures, and processes to properly document and maintain data. | Privacy policies, procedures, and processes have been established and are enforced with IT team members and other employees as necessary. |

### System and Organizations Controls (SOC Type 1, SOC Type 2)

| Yes | No | Best Practice | Explanation |
| --- | --- | ------------- | ----------- |
|  | ● | User access policies are established. | The principles of Least Privilege and Separation of Duties are not currently implemented, as all employees have access to internally stored data. |
|  | ● | Sensitive data (PII/SPII) is confidential/private. | The company currently does not use encryption. |
| ● |  | Data integrity ensures the data is consistent, complete, accurate, and has been validated. | Data integrity is in place. |
|  | ● | Data is available to individuals authorized to access it. | Data is currently accessible to all employees, but access should be restricted to only those individuals who require it to perform their job functions. |

-----------------------------------------------------------------

# Security Recommendation for Botium Toys

Based on the current risk assessment, it is essential that Botium Toys take immediate action to enhance its security posture and address critical gaps in asset management and compliance. The company should prioritize implementing **least privilege access controls** to ensure that employees only have access to the data they need for their specific roles. This should include implementing **separation of duties** to reduce the risk of unauthorized access to sensitive data such as customer cardholder information and personally identifiable information (PII/SPII). Botium Toys should adopt **encryption protocols** for sensitive data such as credit card information to maintain confidentiality, ensuring compliance with industry standards such as PCI DSS.

In addition to addressing data access concerns, Botium Toys must implement a **robust disaster recovery plan** that includes regular **backups** of critical data and a formalized response plan in case of an incident. The absence of disaster recovery protocols and lack of proper backups exposes the company to significant risk in the event of a data breach or system failure. The company should consider installing an **intrusion detection system (IDS)** to proactively identify and mitigate potential threats to the internal network. These measures will help reduce the likelihood of a breach and ensure business continuity in the event of a system compromise.

Finally, Botium Toys should establish a centralized **password management system** to enforce stronger password policies, ensuring compliance with current security standards. Regular password resets and minimal password complexity requirements should be enforced to protect employee and customer data. Additionally, routine monitoring and maintenance schedules for legacy systems should be implemented to mitigate the risks associated with outdated technology. By addressing these key areas—access control, disaster recovery, encryption, and password management—Botium Toys will significantly reduce its risk exposure and enhance its overall security framework.
