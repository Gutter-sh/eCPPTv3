How to set it up in the exam environment
1) Save and run
nano ~/ecppt_exam_journal_aio.sh
# paste script
chmod +x ~/ecppt_exam_journal_aio.sh
~/ecppt_exam_journal_aio.sh
source ~/.bashrc

2) Sync the correct wordlists (important)
sync_wordlists
mkcombo

3) Create your exam workspace using the LOE subnet
makebox ExamNet 10.10.10.0/24
cd ~/pentest-journal/boxes/ExamNet

4) Run automated scan/enum
enum --box ExamNet

5) When you identify the DC / domain

Edit:

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
