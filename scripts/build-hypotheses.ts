import { mkdir, readFile, writeFile } from 'node:fs/promises'

interface Technique {
  id: string
  name: string
  tactics: string[]
  data_sources?: string[]
}

interface HuntTemplate {
  technique: string
  title: string
  severity: 'high' | 'medium'
  hypothesis: string
  logSources: string[]
  investigationSteps: string[]
  validationNotes: string
  falsePositiveNotes: string
  tags: string[]
  kql: string
  spl: string
  elastic: string
  sigma: string
}

const templates: HuntTemplate[] = [
  {
    technique: 'T1110.003',
    title: 'Password spraying against Windows accounts',
    severity: 'high',
    hypothesis: 'A source address produces failed logons for many distinct accounts in a short time window.',
    logSources: ['Windows Security Event 4625'],
    investigationSteps: [
      'Pivot on the source address and time bucket; review targeted accounts, failure reasons, and whether any authentication succeeded afterward.',
      'Compare the activity with the source address’s normal role, known VPN or proxy egress, and the affected accounts’ usual sign-in patterns.',
      'If a success follows the failures, review the account’s subsequent sign-ins and endpoint activity in the same time window.',
    ],
    validationNotes: 'Confirm the failure event and account/IP field mappings in your identity logs. Tune the 15-minute window and account threshold to your normal authentication volume.',
    falsePositiveNotes: 'Shared NAT/VPN egress, identity-provider retries, password-manager errors, and authorized password audits can produce broad failure patterns.',
    tags: ['identity', 'credentials', 'windows'],
    kql: 'SecurityEvent\n| where EventID == 4625\n| summarize target_accounts=dcount(TargetAccount), failures=count() by IpAddress, bin(TimeGenerated, 15m)\n| where target_accounts >= 10',
    spl: 'index=wineventlog EventCode=4625\n| bin _time span=15m\n| stats dc(Account_Name) as target_accounts count as failures by IpAddress _time\n| where target_accounts >= 10',
    elastic: 'event.code:"4625" and source.ip:*',
    sigma: 'title: Password spraying against multiple accounts\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\nlogsource:\n  product: windows\n  service: security',
  },
  {
    technique: 'T1059.001',
    title: 'Unusual PowerShell process execution',
    severity: 'high',
    hypothesis: 'PowerShell launches with encoded, hidden, download, or policy-bypass arguments outside expected administrative activity.',
    logSources: ['Microsoft Defender DeviceProcessEvents', 'Sysmon Event ID 1'],
    investigationSteps: [
      'Review the complete process tree, initiating account, host, command line, and whether the parent process is expected for that user and device.',
      'Pivot to child processes, file writes, script-block or AMSI telemetry, and network connections around the execution time.',
      'Compare the executable path, signer, hash, and command pattern with approved administration and software-deployment activity.',
    ],
    validationNotes: 'Check process command-line and parent-process field availability. The query searches selected strings and will miss other forms of PowerShell abuse.',
    falsePositiveNotes: 'IT automation, software deployment, endpoint management, and incident-response scripts may use encoded or hidden PowerShell arguments.',
    tags: ['execution', 'powershell', 'windows'],
    kql: 'DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-windowstyle hidden", "downloadstring", "-executionpolicy bypass")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
    spl: 'index=sysmon EventCode=1 (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe")\n| where match(lower(CommandLine), "-enc|encodedcommand|windowstyle hidden|downloadstring|executionpolicy bypass")\n| table _time host User Image CommandLine ParentImage',
    elastic: 'process.name:(powershell.exe or pwsh.exe) and process.command_line:(*-enc* or *-encodedcommand* or *downloadstring* or *executionpolicy bypass*)',
    sigma: 'title: Suspicious PowerShell command-line options\ndetection:\n  selection_image:\n    Image|endswith:\n      - \\\\powershell.exe\n      - \\\\pwsh.exe\n  selection_args:\n    CommandLine|contains:\n      - -enc\n      - -encodedcommand\n      - downloadstring\n  condition: selection_image and selection_args\nlogsource:\n  product: windows\n  category: process_creation',
  },
  {
    technique: 'T1003.001',
    title: 'Potential LSASS memory access',
    severity: 'high',
    hypothesis: 'A process other than an approved security or diagnostic tool requests access to LSASS memory.',
    logSources: ['Sysmon Event ID 10', 'Microsoft Defender DeviceProcessEvents'],
    investigationSteps: [
      'Identify the requesting process, signer, hash, command line, user, and parent process; confirm whether it belongs to an approved security or diagnostic tool.',
      'Correlate nearby process creation, memory-access, file-write, and endpoint alert telemetry on the same host.',
      'Review whether similar access occurs across hosts or is limited to a known maintenance window or software rollout.',
    ],
    validationNotes: 'Confirm your sensor records process-access events and that the query’s LSASS and source-process fields are mapped correctly. This is a lead for review, not proof of credential theft.',
    falsePositiveNotes: 'Endpoint protection, EDR, backup, diagnostics, and approved credential-management software may access LSASS-related processes.',
    tags: ['credential-access', 'lsass', 'windows'],
    kql: 'DeviceEvents\n| where ActionType == "OpenProcessApiCall"\n| where AdditionalFields has "lsass.exe"\n| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName',
    spl: 'index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"\n| stats count values(SourceImage) as source_processes by host SourceUser\n| sort -count',
    elastic: 'event.code:"10" and process.name:* and TargetImage:*lsass.exe',
    sigma: 'title: Process access to LSASS\ndetection:\n  selection:\n    EventID: 10\n    TargetImage|endswith: \\\\lsass.exe\n  condition: selection\nlogsource:\n  product: windows\n  service: sysmon',
  },
  {
    technique: 'T1053.005',
    title: 'Unexpected scheduled task creation',
    severity: 'medium',
    hypothesis: 'A new scheduled task is created by an unusual account or with a command path outside approved software locations.',
    logSources: ['Windows Security Event 4698', 'Sysmon Event ID 1'],
    investigationSteps: [
      'Inspect the task name, XML action, trigger, principal, creator, and binary or script path.',
      'Pivot from the creator and action to process, file, and network telemetry around task creation and first execution.',
      'Compare the task and its execution cadence across similar hosts; check whether it aligns with a change or software deployment.',
    ],
    validationNotes: 'Enable and verify task-creation auditing; confirm task XML fields are available and correlate the creation event with process execution telemetry.',
    falsePositiveNotes: 'Software installers, endpoint-management agents, backup tools, and routine operating-system maintenance create scheduled tasks.',
    tags: ['persistence', 'scheduled-task', 'windows'],
    kql: 'SecurityEvent\n| where EventID == 4698\n| project TimeGenerated, Computer, SubjectAccount, TaskName, TaskContent',
    spl: 'index=wineventlog EventCode=4698\n| table _time host SubjectUserName TaskName TaskContent',
    elastic: 'event.code:"4698" and winlog.event_data.TaskName:*',
    sigma: 'title: Scheduled task created\ndetection:\n  selection:\n    EventID: 4698\n  condition: selection\nlogsource:\n  product: windows\n  service: security',
  },
  {
    technique: 'T1547.001',
    title: 'Registry Run key persistence',
    severity: 'high',
    hypothesis: 'A process creates or modifies a common Run or RunOnce key to establish user or system logon persistence.',
    logSources: ['Sysmon Event ID 12/13/14', 'Windows Registry telemetry'],
    investigationSteps: [
      'Review the registry value data, user hive, initiating process, signer, file path, and whether the value points to an existing executable.',
      'Pivot to file creation, process execution, and network events for the referenced binary, then check whether the same value appears on peer hosts.',
      'Compare the change time and account with software installation, logon, or approved configuration-management activity.',
    ],
    validationNotes: 'Confirm registry event coverage and normalize key paths across 32-bit/64-bit views and user hives. Scope monitoring to autorun locations relevant to your environment.',
    falsePositiveNotes: 'Legitimate applications, installers, and endpoint-management software commonly maintain Run and RunOnce values.',
    tags: ['persistence', 'registry', 'windows'],
    kql: 'DeviceRegistryEvents\n| where RegistryKey has_any ("\\\\CurrentVersion\\\\Run", "\\\\CurrentVersion\\\\RunOnce")\n| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName',
    spl: 'index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=14) TargetObject="*\\\\CurrentVersion\\\\Run*"\n| table _time host User Image TargetObject Details',
    elastic: 'registry.path:*\\\\CurrentVersion\\\\Run*',
    sigma: 'title: Registry Run key modification\ndetection:\n  selection:\n    TargetObject|contains: \\\\CurrentVersion\\\\Run\n  condition: selection\nlogsource:\n  product: windows\n  category: registry_event',
  },
  {
    technique: 'T1021.001',
    title: 'Unusual Remote Desktop logons',
    severity: 'medium',
    hypothesis: 'Remote interactive logons originate from unusual source addresses or occur across multiple hosts in a short window.',
    logSources: ['Windows Security Event 4624'],
    investigationSteps: [
      'Pivot on account, source address, and time; review destination hosts, logon type, authentication package, and nearby failed logons.',
      'Compare the source and account with approved remote-access gateways, administrator workflows, and the account’s normal host set.',
      'Review activity after the logon on each destination, including process creation and additional remote logons.',
    ],
    validationNotes: 'Validate logon-type and source-IP mappings, and account for NAT, VPN, jump hosts, and event volume before tuning the host-count threshold.',
    falsePositiveNotes: 'Help-desk support, server administration, VDI, jump hosts, and approved remote-access tools can create broad RDP patterns.',
    tags: ['lateral-movement', 'rdp', 'windows'],
    kql: 'SecurityEvent\n| where EventID == 4624 and LogonType == 10\n| summarize hosts=dcount(Computer), logons=count() by IpAddress, TargetAccount, bin(TimeGenerated, 30m)\n| where hosts > 2',
    spl: 'index=wineventlog EventCode=4624 Logon_Type=10\n| bin _time span=30m\n| stats dc(host) as hosts count as logons by IpAddress TargetUserName _time\n| where hosts > 2',
    elastic: 'event.code:"4624" and winlog.event_data.LogonType:"10"',
    sigma: 'title: Remote interactive logon\ndetection:\n  selection:\n    EventID: 4624\n    LogonType: 10\n  condition: selection\nlogsource:\n  product: windows\n  service: security',
  },
  {
    technique: 'T1047',
    title: 'WMI process execution',
    severity: 'medium',
    hypothesis: 'WMI provider processes launch command interpreters or scripting engines on endpoints where this behavior is uncommon.',
    logSources: ['Sysmon Event ID 1', 'Microsoft Defender DeviceProcessEvents'],
    investigationSteps: [
      'Review the WMI provider’s child process, command line, user, parent process, and host role.',
      'Correlate WMI operational events and remote logons to identify the initiating account and any source host, then pivot to the destination process tree.',
      'Compare the activity with software management, inventory, and monitoring tools used in the environment.',
    ],
    validationNotes: 'Confirm parent-process and WMI event coverage; provider process names can vary, and the query only covers selected child executables.',
    falsePositiveNotes: 'Configuration management, asset inventory, monitoring, and software deployment platforms often use WMI to launch processes.',
    tags: ['execution', 'wmi', 'windows'],
    kql: 'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("wmiprvse.exe", "WmiPrvSE.exe")\n| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "wscript.exe")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine',
    spl: 'index=sysmon EventCode=1 ParentImage="*\\\\WmiPrvSE.exe"\n| table _time host User Image CommandLine ParentCommandLine',
    elastic: 'process.parent.name:"WmiPrvSE.exe" and process.name:(cmd.exe or powershell.exe or rundll32.exe or wscript.exe)',
    sigma: 'title: Suspicious process spawned by WMI provider\ndetection:\n  selection_parent:\n    ParentImage|endswith: \\\\WmiPrvSE.exe\n  selection_child:\n    Image|endswith:\n      - \\\\cmd.exe\n      - \\\\powershell.exe\n      - \\\\rundll32.exe\n  condition: selection_parent and selection_child\nlogsource:\n  product: windows\n  category: process_creation',
  },
  {
    technique: 'T1078',
    title: 'Valid account behavior anomaly',
    severity: 'medium',
    hypothesis: 'A valid account authenticates from unusual locations, at unusual times, or across an unexpectedly broad set of hosts.',
    logSources: ['Windows Security Event 4624', 'Identity provider sign-in logs'],
    investigationSteps: [
      'Compare the account’s source addresses, devices, locations, authentication methods, and target hosts with its established baseline.',
      'Review MFA outcomes, conditional-access decisions, nearby failures, and any privileged actions after the sign-in.',
      'Determine whether the account is human, service, or shared; compare the event with change windows and approved automation.',
    ],
    validationNotes: 'Build user- and service-account-aware baselines. Source IP and location can be distorted by proxies, VPNs, cloud egress, and identity-provider normalization.',
    falsePositiveNotes: 'Travel, VPN use, shared services, scheduled jobs, and changes in cloud egress may create legitimate location or host-count anomalies.',
    tags: ['initial-access', 'identity', 'valid-account'],
    kql: 'SecurityEvent\n| where EventID == 4624\n| summarize source_ips=dcount(IpAddress), hosts=dcount(Computer) by TargetAccount, bin(TimeGenerated, 1h)\n| where source_ips > 3 or hosts > 10',
    spl: 'index=wineventlog EventCode=4624\n| bin _time span=1h\n| stats dc(IpAddress) as source_ips dc(host) as hosts by TargetUserName _time\n| where source_ips > 3 OR hosts > 10',
    elastic: 'event.code:"4624" and user.name:* and source.ip:*',
    sigma: 'title: Successful logon for valid account\ndetection:\n  selection:\n    EventID: 4624\n  condition: selection\nlogsource:\n  product: windows\n  service: security',
  },
  {
    technique: 'T1566.001',
    title: 'Phishing attachment execution',
    severity: 'high',
    hypothesis: 'An email attachment is followed by execution of a script, archive utility, or newly written executable on the recipient endpoint.',
    logSources: ['Email gateway telemetry', 'Microsoft Defender DeviceProcessEvents'],
    investigationSteps: [
      'Correlate the recipient, message identifier, attachment name/hash, delivery time, and endpoint process start.',
      'Review the full process tree and any files written or network connections made by the child process; pivot on hashes and affected recipients.',
      'Check whether the same attachment or sender appears in other mailboxes and whether the execution pattern matches approved business software.',
    ],
    validationNotes: 'Join mail and endpoint events using stable message, recipient, file, or time identifiers. Email-client parentage alone is incomplete and does not establish that a file came from email.',
    falsePositiveNotes: 'Legitimate document workflows, add-ins, browser-based mail, and security tools can create similar parent-child or file-execution patterns.',
    tags: ['phishing', 'initial-access', 'email'],
    kql: 'DeviceProcessEvents\n| where FileName in~ ("wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")\n| where InitiatingProcessFileName in~ ("outlook.exe", "winword.exe", "excel.exe")\n| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine',
    spl: 'index=sysmon EventCode=1 (ParentImage="*\\\\OUTLOOK.EXE" OR ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE")\n| table _time host User Image CommandLine ParentImage',
    elastic: 'process.parent.name:(outlook.exe or winword.exe or excel.exe) and process.name:(wscript.exe or cscript.exe or mshta.exe or rundll32.exe)',
    sigma: 'title: Script host spawned by an email client\ndetection:\n  selection_parent:\n    ParentImage|endswith:\n      - \\\\OUTLOOK.EXE\n      - \\\\WINWORD.EXE\n      - \\\\EXCEL.EXE\n  selection_child:\n    Image|endswith:\n      - \\\\wscript.exe\n      - \\\\cscript.exe\n      - \\\\mshta.exe\n  condition: selection_parent and selection_child\nlogsource:\n  product: windows\n  category: process_creation',
  },
  {
    technique: 'T1059.003',
    title: 'Suspicious Windows command shell activity',
    severity: 'medium',
    hypothesis: 'A Windows command shell launches with discovery, download, encoded, or chained execution arguments.',
    logSources: ['Sysmon Event ID 1', 'Microsoft Defender DeviceProcessEvents'],
    investigationSteps: [
      'Review the full command line, parent process, user, device role, and neighboring commands in the same process tree.',
      'Pivot on referenced files, child processes, destination addresses, and related discovery or authentication events.',
      'Compare the activity with approved scripts, software deployment, troubleshooting, and administrative sessions.',
    ],
    validationNotes: 'String matching is a starting point, not behavioral proof. Confirm command-line collection and adjust terms for localization, quoting, and your telemetry schema.',
    falsePositiveNotes: 'System administration, installers, support scripts, and endpoint-management tools routinely use command shells and common discovery commands.',
    tags: ['execution', 'command-shell', 'windows'],
    kql: 'DeviceProcessEvents\n| where FileName =~ "cmd.exe"\n| where ProcessCommandLine has_any ("whoami", "nltest", "net user", "certutil", "bitsadmin", "&&")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
    spl: 'index=sysmon EventCode=1 Image="*\\\\cmd.exe"\n| where match(lower(CommandLine), "whoami|nltest|net user|certutil|bitsadmin|&&")\n| table _time host User CommandLine ParentImage',
    elastic: 'process.name:"cmd.exe" and process.command_line:(*whoami* or *nltest* or *certutil* or *bitsadmin*)',
    sigma: 'title: Suspicious Windows command shell arguments\ndetection:\n  selection_image:\n    Image|endswith: \\\\cmd.exe\n  selection_args:\n    CommandLine|contains:\n      - whoami\n      - nltest\n      - certutil\n      - bitsadmin\n  condition: selection_image and selection_args\nlogsource:\n  product: windows\n  category: process_creation',
  },
  {
    technique: 'T1110.001',
    title: 'SSH password guessing across Linux accounts',
    severity: 'high',
    hypothesis: 'One source address generates failed SSH authentications for multiple accounts within a short period.',
    logSources: ['Linux authentication logs (auth/authpriv)', 'SSH daemon logs', 'Identity-provider sign-in logs'],
    investigationSteps: [
      'Review the source address, targeted account names, failure reasons, and whether a successful authentication followed the failures.',
      'Pivot from any successful login to the destination host, session activity, privilege changes, and subsequent network connections.',
      'Compare the source with approved scanners, VPN egress, bastions, and expected internet-facing service exposure.',
    ],
    validationNotes: 'The KQL example parses common sshd message text and IPv4/IPv6-like source tokens; verify your Syslog facility, message format, and time-window threshold.',
    falsePositiveNotes: 'Internet background scanning, vulnerability assessments, misconfigured automation, shared NAT, and password rotation can create repeated failures.',
    tags: ['linux', 'ssh', 'authentication', 'brute-force'],
    kql: 'Syslog\n| where Facility in~ ("auth", "authpriv")\n| where SyslogMessage contains "Failed password"\n| extend SourceIp=extract(@"from ([0-9a-fA-F:.]+)", 1, SyslogMessage), TargetUser=extract(@"Failed password for (?:invalid user )?(\\S+)", 1, SyslogMessage)\n| where isnotempty(SourceIp) and isnotempty(TargetUser)\n| summarize failures=count(), targeted_accounts=dcount(TargetUser) by SourceIp, bin(TimeGenerated, 10m)\n| where targeted_accounts >= 5',
    spl: 'index=linux (sourcetype=secure OR sourcetype=auth) "Failed password"\n| rex "Failed password for (?:invalid user )?(?<target_user>\\\\S+) from (?<source_ip>\\\\S+)"\n| bin _time span=10m\n| stats count as failures dc(target_user) as targeted_accounts by source_ip _time\n| where targeted_accounts >= 5',
    elastic: 'event.category:authentication and event.outcome:failure and process.name:sshd and source.ip:*',
    sigma: 'title: Repeated SSH authentication failures\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  selection:\n    message|contains: Failed password\n  condition: selection',
  },
  {
    technique: 'T1098.004',
    title: 'Unexpected SSH authorized-keys change',
    severity: 'high',
    hypothesis: 'An SSH authorized_keys file is created or modified outside a known account-management or configuration-management change.',
    logSources: ['Linux endpoint file events', 'Linux auditd file activity', 'EDR file telemetry'],
    investigationSteps: [
      'Identify the affected host and account from the file path, then review the modifying process, user, parent process, and change time.',
      'Compare the new key fingerprint and associated account with approved access records; do not treat the public key itself as proof of misuse.',
      'Pivot to nearby SSH logins, privilege changes, source hosts, and other persistence changes on the affected system.',
    ],
    validationNotes: 'Confirm that endpoint or audit telemetry records file creation and modification for home-directory .ssh paths. Paths and event names vary by agent and operating system.',
    falsePositiveNotes: 'User onboarding, key rotation, configuration-management tools, automated deployment, and administrator access maintenance commonly update authorized_keys.',
    tags: ['linux', 'ssh', 'persistence', 'account-manipulation'],
    kql: 'DeviceFileEvents\n| where FileName =~ "authorized_keys"\n| where FolderPath contains "/.ssh/"\n| where ActionType in~ ("FileCreated", "FileModified")\n| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName',
    spl: 'index=linux* ("authorized_keys" OR ".ssh")\n| eval key_file=coalesce(file.path, path, TargetFilename)\n| where like(key_file, "%/.ssh/authorized_keys")\n| stats count values(process) as modifying_processes values(user) as modifying_users by host key_file',
    elastic: 'file.path:* and file.name:"authorized_keys" and event.type:(creation or change)',
    sigma: 'title: SSH authorized_keys file modification\nlogsource:\n  product: linux\n  category: file_event\ndetection:\n  selection:\n    TargetFilename|endswith: /.ssh/authorized_keys\n  condition: selection',
  },
  {
    technique: 'T1078.004',
    title: 'Cloud account sign-in from multiple source addresses',
    severity: 'medium',
    hypothesis: 'A cloud identity completes successful sign-ins from several source addresses in a short interval that is unusual for that identity.',
    logSources: ['Microsoft Entra ID SigninLogs', 'Cloud identity-provider authentication events'],
    investigationSteps: [
      'Review the account, source addresses, device identifiers, locations, authentication methods, MFA results, and conditional-access decisions.',
      'Compare the addresses and sign-in pattern with the user’s role, known VPN or secure web gateway egress, and normal service-account behavior.',
      'For unexplained successful sign-ins, pivot to application access, privilege changes, token activity, and endpoint sessions in the same time window.',
    ],
    validationNotes: 'The KQL example uses the Microsoft Sentinel SigninLogs schema. Normalize success values, user/IP fields, and location fields before adapting SPL or Elastic queries.',
    falsePositiveNotes: 'Corporate VPNs, mobile networks, cloud proxies, travel, shared egress, and identity-provider address normalization can produce multiple legitimate source addresses.',
    tags: ['cloud', 'identity', 'authentication', 'baseline'],
    kql: 'SigninLogs\n| where ResultType == "0"\n| summarize source_addresses=dcount(IPAddress), countries=dcount(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName, bin(TimeGenerated, 1h)\n| where source_addresses >= 3 or countries >= 2',
    spl: 'index=azure:signin (ResultType=0 OR result=0)\n| eval account=coalesce(UserPrincipalName, user), source_ip=coalesce(IPAddress, src)\n| bin _time span=1h\n| stats dc(source_ip) as source_addresses count by account _time\n| where source_addresses >= 3',
    elastic: 'event.dataset:azure.signinlogs and event.outcome:success and user.name:* and source.ip:*',
    sigma: 'title: Successful cloud account sign-in\nlogsource:\n  product: azure\n  service: signinlogs\ndetection:\n  selection:\n    ResultType: "0"\n  condition: selection',
  },
]

const techniques: Technique[] = JSON.parse(await readFile('public/data/techniques.json', 'utf8'))
const techniqueMap = new Map(techniques.map(technique => [technique.id, technique]))
const hypotheses = templates.map(template => {
  const technique = techniqueMap.get(template.technique)
  return {
    id: `hyp-${template.technique.toLowerCase().replace('.', '-')}`,
    title: template.title,
    origin: `template:${template.technique}`,
    generated: true,
    needs_review: false,
    attack_techniques: [template.technique],
    severity: template.severity,
    date: new Date().toISOString().slice(0, 10),
    why: 'Deterministic analyst-authored hunt template. Validate table names and event fields against your telemetry before running.',
    log_sources: template.logSources,
    hypothesis: template.hypothesis,
    investigation_steps: template.investigationSteps,
    validation_notes: template.validationNotes,
    false_positive_notes: template.falsePositiveNotes,
    queries: {
      kql: { language: 'KQL · Sentinel / Defender', query: template.kql },
      spl: { language: 'SPL · Splunk', query: template.spl },
      elastic: { language: 'Elastic KQL', query: template.elastic },
      sigma: {
        language: 'Sigma',
        query: template.sigma,
        sigma_link: 'https://github.com/SigmaHQ/sigma',
      },
    },
    tags: template.tags,
    ...(technique ? { tactics: technique.tactics } : {}),
  }
})

await mkdir('public/data', { recursive: true })
await writeFile('public/data/hunt-hypotheses.json', JSON.stringify(hypotheses))
console.log(`Built ${hypotheses.length} deterministic hunt hypotheses`)
