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
    tags: ['execution', 'command-shell', 'windows'],
    kql: 'DeviceProcessEvents\n| where FileName =~ "cmd.exe"\n| where ProcessCommandLine has_any ("whoami", "nltest", "net user", "certutil", "bitsadmin", "&&")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
    spl: 'index=sysmon EventCode=1 Image="*\\\\cmd.exe"\n| where match(lower(CommandLine), "whoami|nltest|net user|certutil|bitsadmin|&&")\n| table _time host User CommandLine ParentImage',
    elastic: 'process.name:"cmd.exe" and process.command_line:(*whoami* or *nltest* or *certutil* or *bitsadmin*)',
    sigma: 'title: Suspicious Windows command shell arguments\ndetection:\n  selection_image:\n    Image|endswith: \\\\cmd.exe\n  selection_args:\n    CommandLine|contains:\n      - whoami\n      - nltest\n      - certutil\n      - bitsadmin\n  condition: selection_image and selection_args\nlogsource:\n  product: windows\n  category: process_creation',
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
    ...(technique ? { tactic: technique.tactics } : {}),
  }
})

await mkdir('public/data', { recursive: true })
await writeFile('public/data/hunt-hypotheses.json', JSON.stringify(hypotheses))
console.log(`Built ${hypotheses.length} deterministic hunt hypotheses`)
