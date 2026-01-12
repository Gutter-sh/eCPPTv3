# eCPPT Exam Environment Setup (Pentest Journal + Automation)

This section shows how to deploy the **eCPPT exam-tuned pentest journal** and run the automated baseline enumeration inside the **browser attackbox** environment.

---

## 1) Save and run the installer script

```bash
nano ~/ecppt_exam_journal_aio.sh
# paste the script contents, save, exit

chmod +x ~/ecppt_exam_journal_aio.sh
~/ecppt_exam_journal_aio.sh

# load aliases / PATH helpers
source ~/.bashrc

2) Sync the correct wordlists (important)
sync_wordlists
mkcombo

3) Create your exam workspace using the LOE subnet
Replace the subnet with the one provided in the Letter of Engagement (LOE):
makebox ExamNet 10.10.10.0/24
cd ~/pentest-journal/boxes/ExamNet

4) Run automated scan/enum
enum --box ExamNet

Outputs will be written to:
01_scans/
hosts/<ip>/scans/
hosts/<ip>/enum/
hosts/<ip>/loot/

5) When you identify the DC / domain
Edit the box config:
nano box.conf

Set:
DOMAIN="DOMAIN.LOCAL"
DC_IP="x.x.x.x"

Populate 04_ad/users.txt as you discover naming patterns, then rerun:
enum --box ExamNet

6) Crack any Kerberos hashes with John
crack_john hosts/<ip>/loot/asrep.txt ~/pentest-journal/wordlists/passwords/xato-net-10-million-passwords-10000.txt
crack_john hosts/<ip>/loot/asrep.txt ~/pentest-journal/wordlists/passwords/seasons.txt
crack_john hosts/<ip>/loot/asrep.txt ~/pentest-journal/wordlists/passwords/months.txt
