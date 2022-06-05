# PAEMAL
(PHP Analysis Environment Applied to Malware Machine Learning)

    Sidney Lima, Sthéfano Silva, Ricardo Pinheiro et al. 
    Next-Generation Antivirus endowed with Web-Server SandBox Applied to Audit Fileless Attack, 
    23 February 2022, PREPRINT (Version 1) available at Research Square 
    https://doi.org/10.21203/rs.3.rs-390916/v1

## Commercial Antiviruses Limitation

Despite being questioned more than a decade ago, the modus operandi of the antiviruses is based on signatures when the suspicious file is queried in blacklisted named databases. Therefore, it is enough that the hash of the investigated file is not in the blacklist of the antivirus so that the malware is not detected. The hash functions as a unique identifier for a specific file. So, knowing the limitations of commercial antiviruses, it is not a difficult task to develop and distribute variants of a malicious application. To do this, simply make minor changes to the original malware with routines that effectively have no utility for the program, such as repeating loops and conditional deviations without instructions in their scopes. These unuseful changes, however, make the hash of the modified malware different from the hash of the original malware. Consequently, the malware, incremented with null routines, will not be detected by the antivirus which catalogued the original malware. It is worth noting the existence of botnets responsible for creating and distributing variants, in an automated way, of the same original malware. We conclude that antiviruses, based on signatures, have null effectiveness when subjected to variants of the same malware.

Through the VirusTotal platform, the proposed paper investigates 86 commercial antivirus with their respective results presented in Table 1. We have utilized 200 malicious PHPs obtained from the PAEMAL base. The aim of this paper is to verify the amount of virtual threats catalogued by the antiviruses. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, the larger the malware database, named blacklist, best tends to be the defense provided by the antiviruses. Fig. 2 shows the diagram of the methodology proposed in the Block diagram. Initially, the Jar Malwares are sent to the server belonging to the VirusTotal platform. After that, PHP Files are analyzed by the 86 commercial antiviruses linked to VirusTotal. Soon, the antivirus provide its diagnostics to the PHP Files submitted to the platform. VirusTotal allows the possibility of issuing three different types of diagnoses; malware, benign and omission.

As for the first possibility of VirusTotal, the antivirus detects the malignancy of the suspicious file. In the proposed experimental environment, all submitted files are malware documented by the incident responders. Soon, the antivirus hits when it detects the malignancy of the investigated file. Malware detection indicates that the antivirus provides a robust service against cyber-intrusions. In the second possibility, the antivirus certifies the benignity of the file investigated. Therefore, in the proposed study, when the antivirus claims the benignity of the file, it is a case of false negative since all samples are malicious. It means that the investigated file is malware, however, the antivirus attests benign, in a mistaken way. In the third possibility, the antivirus does not issue an opinion about the suspicious file. The omission indicates that the file investigated has never been evaluated by the antivirus so it has small robustness to evaluate it in real time. The omission of the diagnosis, by the antivirus, points to its limitation on large-scale services.

Table 1 shows the results achieved by the 86 commercial antiviruses evaluated. Ikarus antivirus obtained the best performance being able to detect 78.50% of the malware investigated. A great adversity, in the fight against malicious applications, is the fact that the antivirus manufacturers do not share their respective blacklists of malwares due to commercial disputes. Through the analysis of Table 1, the proposed paper points to an aggravating factor of this adversity; the same antivirus manufacturer does not even share its databases among its distinct antiviruses. Note, for example, that McAfee-GW-Edition and McAfee antivirus products belong to the same company. Their blacklists are not shared with each other. Therefore, the commercial strategies, of the same company, hinder the chartering of malwares. It is complemented that antivirus manufacturers are not necessarily concerned with avoiding cyber-invasions, but in optimizing their commercial incomes.

Malware detection ranged from 0% to 78.50%, depending on the antivirus investigated. On average, the 86 antiviruses were able to detect 16.82% of malware evaluated, with a standard deviation of 21.88. The high standard deviation indicates that the detection of malicious samples may suffer abrupts variations depending on the chosen antivirus. We concluded that protection, against cyber invasions, is due to the choice of a robust antivirus endowed with a large and updated blacklist. On average, the antiviruses attested false negatives in 49.49% of the cases, with standard deviation of 38.32. Atone to the benignity of a malware may imply unrecoverable losses. A person or institution, for instance, would rely on a certain malicious application when, in fact, it is a malware. Also as an unfavorable aspect, about 57% did not issue an opinion on any of the 200 malicious samples. On average, the antiviruses were omitted in 33.68% of the cases, with a standard deviation of 45.61. The omission of the diagnosis points to the limitation of the antivirus regarding the detection of malwares in real time.

It includes as adversity, in the fight against malicious applications, the fact that commercial antivirus does not have a standard in the classification of malwares as seen in Table 2. We chose 3 of the 998 Jar malwares to exemplify the miscellaneous of rankings given by commercial antivirus. Because there is no default, the antivirus will give them the names they want. For example, McAfee-GW-Edition can identify a PHP malware such as "HEUR_HTJS. HDJSFN "and McAfee, belonging to the same company, identify it as" JS. Blacole. H ". Therefore, the lack of a pattern hinders the cyber-surveillance strategies as each category of malware should have different treatments (vaccines). We concluded that it is not feasible to learn the supervised machine aiming to recognize the standard of PHP malware categories. Due to this confusing tangle of MultiClass Classification, provided by the experts (antiviruses) as seen in Table 2, it is statistically difficult that some machine learning technique acquires generalization capability.

###### Table 1 Results of 86 commercial antiviruses.

| Antivirus            | Detection (%) | False negative (%) | Omission (%) |
|----------------------|---------------|--------------------|--------------|
| Ikarus               | 78.50         | 16.00              | 5.50         |
| GData                | 59.00         | 39.50              | 1.50         |
| AegisLab             | 55.50         | 42.50              | 2.00         |
| Avast                | 54.50         | 45.50              | 0.00         |
| MAX                  | 54.50         | 42.50              | 3.00         |
| AVG                  | 54.00         | 46                 | 0.00         |
| Kaspersky            | 50.50         | 48.00              | 1.50         |
| ZoneAlarm            | 50.50         | 48                 | 1.50         |
| Avira                | 49.00         | 50.00              | 1.00         |
| MicroWorld-eScan     | 47.00         | 53.00              | 0.00         |
| BitDefender          | 47.00         | 51.50              | 1.50         |
| Ad-Aware             | 47.00         | 50.50              | 2.50         |
| Emsisoft             | 47.00         | 53.00              | 0.00         |
| ALYac                | 46.50         | 52.00              | 1.50         |
| Baidu                | 46.50         | 52.00              | 1.50         |
| Bkav                 | 45.50         | 53.50              | 1.00         |
| McAfee-GW-Edition    | 45.50         | 53.50              | 1.00         |
| Arcabit              | 45.00         | 55.00              | 0.00         |
| McAfee               | 45.00         | 54.50              | 0.50         |
| Antiy-AVL            | 44.00         | 54.00              | 2.00         |
| F-Secure             | 43.00         | 54.00              | 3.00         |
| Comodo               | 40.50         | 59.50              | 0.00         |
| Symantec             | 39.50         | 60.50              | 0.00         |
| ESET-NOD32           | 39.50         | 60.50              | 0.00         |
| Qihoo-360            | 34.00         | 64.50              | 1.50         |
| Cyren                | 33.00         | 67.00              | 0.00         |
| Microsoft            | 30.50         | 69.00              | 0.50         |
| Rising               | 29.50         | 69.50              | 1.00         |
| Fortinet             | 28.50         | 71.50              | 0.00         |
| Sophos               | 27.00         | 73.00              | 0.00         |
| TrendMicro-HouseCall | 24.00         | 75.00              | 1.00         |
| NANO-Antivirus       | 9.00          | 89.50              | 1.50         |
| CAT-QuickHeal        | 7.50          | 92.50              | 0.00         |
| Tencent              | 7.50          | 92.00              | 0.50         |
| AVware               | 7.50          | 91.00              | 1.50         |
| DrWeb                | 5.50          | 94.50              | 0.00         |
| F-Prot               | 5.00          | 94.50              | 0.50         |
| TrendMicro           | 4.00          | 93.00              | 3.00         |
| ClamAV               | 3.50          | 94.50              | 2.00         |
| VIPRE                | 3.50          | 96.00              | 0.50         |
| TotalDefense         | 2.50          | 97.00              | 0.50         |
| Jiangmin             | 2.50          | 96.00              | 1.50         |
| AhnLab-V3            | 2.00          | 98.00              | 0.00         |
| K7GW                 | 1.50          | 98.50              | 0.00         |
| K7AntiVirus          | 1.50          | 98.50              | 0.00         |
| VBA32                | 1.00          | 98.50              | 0.50         |
| nProtect             | 0.50          | 44.50              | 55.00        |
| ViRobot              | 0.50          | 99.50              | 0.00         |
| Yandex               | 0.50          | 98.50              | 1.00         |
| Panda                | 0.50          | 99.50              | 0.00         |
| CMC                  | 0.00          | 99.50              | 0.50         |
| Malwarebytes         | 0.00          | 92.50              | 7.50         |
| Zillya               | 0.00          | 96.00              | 4.00         |
| SUPERAntiSpyware     | 0.00          | 99.00              | 1.00         |
| TheHacker            | 0.00          | 99.50              | 0.50         |
| Invincea             | 0.00          | 0.00               | 100.00       |
| Paloalto             | 0.00          | 0.00               | 100.00       |
| SentinelOne          | 0.00          | 1.00               | 99.00        |
| Webroot              | 0.00          | 75.00              | 25.00        |
| Kingsoft             | 0.00          | 99.50              | 0.50         |
| Endgame              | 0.00          | 0.50               | 99.50        |
| Cylance              | 0.00          | 0.00               | 100.00       |
| Zoner                | 0.00          | 99.50              | 0.50         |
| CrowdStrike          | 0.00          | 0.00               | 100.00       |
| Alibaba              | 0.00          | 1.50               | 98.50        |
| Agnitum              | 0.00          | 0.50               | 99.50        |
| ByteHero             | 0.00          | 0.50               | 99.50        |
| Norman               | 0.00          | 0.00               | 100.00       |
| ahnlab               | 0.00          | 0.00               | 100.00       |
| AntiVir              | 0.00          | 0.00               | 100.00       |
| Commtouch            | 0.00          | 0.00               | 100.00       |
| VirusBuster          | 0.00          | 0.00               | 100.00       |
| NOD32                | 0.00          | 0.00               | 100.00       |
| eSafe                | 0.00          | 0.00               | 100.00       |
| eTrust-Vet           | 0.00          | 0.00               | 100.00       |
| Authentium           | 0.00          | 0.00               | 100.00       |
| Prevx                | 0.00          | 0.00               | 100.00       |
| Sunbelt              | 0.00          | 0.00               | 100.00       |
| PCTools              | 0.00          | 0.00               | 100.00       |
| a-squared            | 0.00          | 0.00               | 100.00       |
| WhiteArmor           | 0             | 41.00              | 59.00        |
| Command              | 0             | 0.00               | 100.00       |
| SAVMail              | 0             | 0.00               | 100.00       |
| FileAdvisor          | 0             | 0.00               | 100.00       |
| Ewido                | 0             | 0.00               | 100.00       |
| Webwasher-Gateway    | 0             | 0.00               | 100.00       |

###### Table 2 Miscellaneous classifications of commercial antiviruses.

| Antivirus            | VirusShare_f0cba054906c17c94b6852c6088b47b0.php | VirusShare_13f71688e77649255460d68258f3e450.php | VirusShare_d293667cf4aad8aece2b86258462bcdb.php |
|----------------------|-------------------------------------------------|-------------------------------------------------|-------------------------------------------------|
| Ikarus               | Trojan.JS.Tadtruss                              | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| GData                | Benign                                          | Win.Trojan.Downloader-68                        | Benign                                          |
| AegisLab             | Trojan.Script.Agent.dtkph                       | Benign                                          | Benign                                          |
| Avast                | Benign                                          | Suspicious_GEN.F47V0405                         | Suspicious_GEN.F47V0614                         |
| MAX                  | EXP/Blacole.EB.4                                | malware                                         | malware                                         |
| AVG                  | JS:Decode-DB                                    | PHP:Multicom-A                                  | JS:Agent-DWO                                    |
| Kaspersky            | Win.Trojan.Iframe-68                            | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| ZoneAlarm            | Benign                                          | Benign                                          | Benign                                          |
| Avira                | Benign                                          | Benign                                          | Benign                                          |
| MicroWorld-eScan     | Benign                                          | Benign                                          | JS.TrojanjQuery.8C8B                            |
| BitDefender          | Trojan.JS.Iframe.wq                             | Benign                                          | HEUR:Trojan.Script.Generic                      |
| Ad-Aware             | Benign                                          | Benign                                          | Benign                                          |
| Emsisoft             | Trojan.JS.IFrame.ANM                            | Benign                                          | HTML/Phishing.m                                 |
| ALYac                | JS/BlacoleRef.E                                 | JS.Redirector.AX                                | Benign                                          |
| Baidu                | Trojan.JS.IFrame.ANM                            | Benign                                          | Benign                                          |
| Bkav                 | Omission                                        | Omission                                        | Omission                                        |
| McAfee-GW-Edition    | HEUR_HTJS.HDJSFN                                | Benign                                          | Benign                                          |
| Arcabit              | Exploit                                         | TrojanDownloader:PHP/RunShell.A                 | Benign                                          |
| McAfee               | JS.Blacole.H                                    | PHP/SillyDlScript.HFI                           | Benign                                          |
| Antiy-AVL            | Malware                                         | PHP/Downloader.A                                | HTML/Infected.WebPage.Gen2                      |
| F-Secure             | TrojWare.JS.Agent.exi                           | Benign                                          | TrojWare.JS.Agent.CUS                           |
| Comodo               | Trojan.JS.IFrame.ANM                            | Benign                                          | Benign                                          |
| Symantec             | JS/IFrame.HC.gen                                | PHP/Downldr.C                                   | Benign                                          |
| ESET-NOD32           | Trojan.Gen.NPE                                  | Downloader                                      | Trojan.Gen.NPE                                  |
| Qihoo-360            | virus.html.gen03.698                            | Malware.Radar01.Gen                             | virus.js.qexvmc.1                               |
| Cyren                | Mal/Iframe-W                                    | Trojan.PHP.Agent                                | Trojan.JS.Script                                |
| Microsoft            | Benign                                          | Benign                                          | Benign                                          |
| Rising               | Troj.Js.Iframe!c                                | Backdoor.Ircbot.Adds!c                          | Benign                                          |
| Fortinet             | JS/Kriptik.CP!tr                                | Benign                                          | HTML/Phishing.M!tr                              |
| Sophos               | JS/Exploit-Blacole.da                           | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| TrendMicro-HouseCall | JS/Kryptik.CP                                   | PHP/Agent.T                                     | Benign                                          |
| NANO-Antivirus       | Trojan.JS.IFrame.ANM                            | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| CAT-QuickHeal        | Benign                                          | Benign                                          | Benign                                          |
| Tencent              | Js.Trojan.Iframe.Ectv                           | Php.Trojan.Downloader.Dzud                      | Benign                                          |
| AVware               | Trojan.JS.IFrame.ANM                            | Benign                                          | JS:Trojan.JS.Agent.SJP                          |
| DrWeb                | Trojan.JS.IFrame.ANM                            | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| F-Prot               | Benign                                          | Benign                                          | Benign                                          |
| TrendMicro           | Benign                                          | Benign                                          | Benign                                          |
| ClamAV               | JS:Decode-DB                                    | PHP:Multicom-A                                  | JS:Agent-DWO                                    |
| VIPRE                | Benign                                          | Benign                                          | Benign                                          |
| TotalDefense         | Trojan.JS.IFrame.ANM                            | Benign                                          | Benign                                          |
| Jiangmin             | JS/IFrame.HC.gen                                | PHP/Downldr.C                                   | Trojan.IILU-2                                   |
| AhnLab-V3            | Benign                                          | Benign                                          | Benign                                          |
| K7GW                 | Benign                                          | Benign                                          | Benign                                          |
| K7AntiVirus          | Exploit                                         | Benign                                          | Benign                                          |
| VBA32                | Benign                                          | BackDoor.Perl.Shellbot.aa                       | Benign                                          |
| nProtect             | Omission                                        | Omission                                        | Omission                                        |
| ViRobot              | Exploit:JS/Blacole                              | Trojan.Script.Agent.vrebc                       | Benign                                          |
| Yandex               | Benign                                          | Benign                                          | Benign                                          |
| Panda                | Benign                                          | Benign                                          | Benign                                          |
| CMC                  | Trojan.JS.IFrame.ANM                            | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| Malwarebytes         | JS/Exploit-Blacole.da                           | Backdoor.IRCBot.ADDS                            | HTML/Phishing.m                                 |
| Zillya               | JS.IFrame.151                                   | Benign                                          | Benign                                          |
| SUPERAntiSpyware     | Trojan.JS.Obfuscator.aa                         | Backdoor.IRCBot.ADDS                            | JS:Trojan.JS.Agent.SJP                          |
| TheHacker            | Benign                                          | Benign                                          | Troj.Script.Generic!c                           |
| Invincea             | Omission                                        | Omission                                        | Omission                                        |
| Paloalto             | Omission                                        | Omission                                        | Omission                                        |
| SentinelOne          | Omission                                        | Omission                                        | Omission                                        |
| Webroot              | Trojan/Script.Gen                               | Backdoor.PHP.ml                                 | Benign                                          |
| Kingsoft             | Benign                                          | Benign                                          | Trojan/JS.Agent.cus                             |
| Endgame              | Omission                                        | Omission                                        | Omission                                        |
| Cylance              | Omission                                        | Omission                                        | Omission                                        |
| Zoner                | Benign                                          | Benign                                          | Benign                                          |
| CrowdStrike          | Omission                                        | Omission                                        | Omission                                        |
| Alibaba              | Omission                                        | Omission                                        | Omission                                        |
| Agnitum              | Omission                                        | Omission                                        | Omission                                        |
| ByteHero             | Omission                                        | Omission                                        | Omission                                        |
| Norman               | Omission                                        | Omission                                        | Omission                                        |
| ahnlab               | Omission                                        | Omission                                        | Omission                                        |
| AntiVir              | Omission                                        | Omission                                        | Omission                                        |
| Commtouch            | Omission                                        | Omission                                        | Omission                                        |
| VirusBuster          | Omission                                        | Omission                                        | Omission                                        |
| NOD32                | Omission                                        | Omission                                        | Omission                                        |
| eSafe                | Omission                                        | Omission                                        | Omission                                        |
| eTrust-Vet           | Omission                                        | Omission                                        | Omission                                        |
| Authentium           | Omission                                        | Omission                                        | Omission                                        |
| Prevx                | Omission                                        | Omission                                        | Omission                                        |
| Sunbelt              | Omission                                        | Omission                                        | Omission                                        |
| PCTools              | Omission                                        | Omission                                        | Omission                                        |
| a-squared            | Omission                                        | Omission                                        | Omission                                        |
| WhiteArmor           | Omission                                        | Omission                                        | Omission                                        |
| Command              | Omission                                        | Omission                                        | Omission                                        |
| SAVMail              | Omission                                        | Omission                                        | Omission                                        |
| FileAdvisor          | Omission                                        | Omission                                        | Omission                                        |
| Ewido                | Omission                                        | Omission                                        | Omission                                        |
| Webwasher-Gateway    | Omission                                        | Omission                                        | Omission                                        |
## Materials and Methods

This present paper aims to elaborate the PAEMAL (PHP Analysis Environment Applied to Malware Machine Learning), a database which allows the classification of PHP files between malicious and benign. PAEMAL is composed of 200 PHP malware files and 1000 other benign PHP files. In regard to virtual plagues, PAEMAL extracted malicious PHP files from VirusShare which is a repository of malware samples to provide security researchers, incident responders, forensic analysts, and the morbidly curious access to samples of live malicious code. In order to catalog the 200 samples of PHP malwares, it was necessary to acquire and analyze, by authorial script, about 1.3 million malwares from the reports updated by VirusShare daily. In digital forensic practice, web-hosting business often works in a disintegrated manner and does not share information with incident responders. In case of denunciations, web-hosting providers simply rebuild a new virtual server instance of cataloging and make available the suspicious server-side files (usually Phps scripts) to the incident researchers. On the other hand, VirusShare catalogs, every day, dozens of conventional malwares, such as PE files, since the antivirus archives them as soon as the victim notifies anomalous behaviors on their personal computer. So the proposed paper claims that it is necessary to integrate WEB-hosting providers and cyber-surveillance companies targeting Server-side malware sharing.

Regarding the benign PHP files, the catalog was given from native scripts of open source tools such as phpMyAdmin. It is emphasized that all benign files were submitted to the VirusTotal audit. Therefore, the samples of benign PHP files, contained in the PAEMAL, had their benevolence attested by the world's leading commercial antiviruses companies.. The results obtained corresponding to the analyses of the benign PHP files and malwares, resulting from the audit of VirusTotal, are available for consultation in the virtual address of PAEMAL.

If there was no treatment in PAEMAL, there would be a tendency of higher hits in the majority class (benign) and high error rate in the minority class (malware). The explanation is because, in the PAEMAL database, the number of benign samples and malwares are unequal: 200 and 1000, respectively. Therefore, when employing unbalanced databases, the accuracy rates of the classifiers can be favored if they are tendentious in relation to the majority class. Aiming not to favor biased classifiers, the proposed paper employs a strategy inspired by biomedical engineering works. In the health area, the presence of an abnormality (e.g. cancer) occurs every thousand diagnoses of healthy patients. Then, the biomedical strategy concerns to repeating the training according to the ratio between the majority and minority classes (200:1000 = 5 iterations). In our paper, for each five iterations, a distinct package of 200 samples of the major class (benign) is presented to the 200 samples of the minority class (malware). In this way, the non-favoring of tendentious classifiers is guaranteed, allied to the maintenance of the diversity of the different samples, from the majority class (benign), contained in the database.

In clinical practice, the absorption of a malignant sample (e.g., cancer) leads to a false negative. It is worth noting that the patient's chances of recovery are associated with early detection of the tumor. Then, the proposed paper is inspired by the state-of-the-art methodological care of biomedical engineering in order to reserve relevant amounts of benign and malware specimens in separate packages for training and testing. Therefore, assuming a sample reserved for testing with little or no instance of the malware class, then the classification, tendentious to the benign class, would have its favored hit rate. Therefore, the proposed paper presents the methodological care to select equally, randomly, benign and malware samples destined for training and testing.
The purpose of PAEMAL dataset creation is to give a full possibility that the proposed methodology being replicated by third parties in future works. Therefore, PAEMAL freely makes available all its benign and malware samples:

• Virustotal audits,

• Dynamic analysis of our Web-Server Next Generation Sandbox. 

In its virtual address, PAEMAL also provides its 1000 benign PHP files. In addition, our base displays the relationship of all other 200 PHP files, this time, malwares. Then, there is the possibility of acquiring all malwares, employed by PAEMAL, through the establishment of agreement and submission to the terms of use of ViruShare. It is concluded that our PAEMAL database enables transparency and impartiality to research, in addition to demonstrating the truthfulness of the results achieved. Then, PAEMAL is expected to serve as a basis for the creation of new scientific works targeting new Web-Server Next Generation Antivirus.
