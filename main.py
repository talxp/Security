import hashlib
import os
import math
from collections import Counter
import pyotp

#Προσθήκη Salt
def add_Salt(FileName):
    #Δημιουργία τυχαίου Salt 16Bytes
    salt=os.urandom(16)
    #Διάβασμα αρχείου
    with open(FileName, "rb") as f:
        data=f.read()
    #Προσθήκη Salt στο αρχείο
    saltedData=salt+data    
    return salt,saltedData

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

#Ταυτοποίηση με 2FA (Two-Factor Authentication) 
#για να διασφαλίσουμε ότι μόνο εξουσιοδοτημένοι χρήστες μπορούν να υπολογίσουν hash, 
#να κάνουν έλεγχο ακεραιότητας 
# και να υπολογίσουν την εντροπία του αρχείου.
def auth_2FA():
    #Δημιουργία ενός τυχαίου μυστικού κωδικού για το 2FA 
    secret_code=pyotp.random_base32()
    #Δημιουργία ενός αντικειμένου TOTP (Time-based One-Time Password) χρησιμοποιώντας το μυστικό κωδικό 
    totp=pyotp.TOTP(secret_code)
    print("Ο τρέχων κωδικός 2FA (Μιας χρήσης) είναι:", totp.now())
    user_code=input("Εισάγετε τον κωδικό 2FA:")
    #Επαλήθευση του κωδικού που εισήγαγε ο χρήστης με τον τρέχοντα κωδικό που δημιουργήθηκε από το αντικείμενο TOTP.
    if totp.verify(user_code):
        print("Η ταυτοποίηση με 2FA ήταν επιτυχής.")
        return True
    else:
        print("Λάθος κωδικός 2FA.")
        return False
    
    
#Υπολογισμός της εντροπίας ενός αρχείου
def calculate_entyropy(file_name):
    #Ανοίγουμε το αρχείο σε δυαδική μορφή και διαβάζουμε τα δεδομένα του
    with open(file_name, "rb") as f:
        data = f.read()
    #Ελέγχουμε αν το αρχείο είναι άδειο, αν ναι επιστρέφουμε εντροπία 0.0
    if len(data) == 0:
        return 0.0
    #Χρησιμοποιούμε την κλάση Counter για να μετρήσουμε τη συχνότητα εμφάνισης κάθε byte στο αρχείο
    byte_counts = Counter(data)
    total_bytes = len(data)
    entropy = 0.0
    #Υπολογίζουμε την εντροπία χρησιμοποιώντας τον τύπο: H = -Σ(p(x) * log2(p(x))) όπου p(x) είναι 
    #η πιθανότητα εμφάνισης κάθε byte στο αρχείο
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    
    return entropy

#Έλεγχος ακεραιότητας αρχείων
def hash_integrityCheck(hashFile, giveFile, algorithm):
    
    if not os.path.exists(hashFile) or os.path.getsize(hashFile) == 0:
        print("Πρώτη εγγραφή, δεν υπάρχει προηγούμενο hash.")
        return
    
    #Πέρνει το hash file και ξεχωρίζει το Salt με το Hash 
    with open(hashFile, "r") as f:
        #Αποθηκεύει το Salt του αποθηκευμένου hash file  
        storedSalt = bytes.fromhex(f.readline().strip())
        #Αποθηκεύει το Hash του αποθηκευμένου hash file  
        storedHash = f.readline().strip()
    
    #Διαβάζει το τρέχον αρχείο 
    with open(giveFile, "rb") as f:
        readFile = f.read()
    
    #Προσθέτει το παλιό Salt με το τρέχονν αρχείο
    saltedData = storedSalt + readFile
    
    #Υπολογίζει το τρέχον hash για το τρέχον Salted File ανάλογα με τον αλγόριθμο που έχει επιλέξει
    if algorithm == "md5":
        currentHash = hashlib.md5(saltedData).hexdigest()
    elif algorithm == "sha256":
        currentHash = hashlib.sha256(saltedData).hexdigest()
    elif algorithm == "sha3":
        currentHash = hashlib.sha3_256(saltedData).hexdigest()
    elif algorithm == "sha256double":
        firstHash = hashlib.sha256(saltedData).hexdigest()
        currentHash = hashlib.sha256(firstHash.encode()).hexdigest()
    
    #Ελέγχει αν το τρέχον hash είναι ίδιο με το αποθηκευμένο hash
    if currentHash == storedHash:
        print("Το αρχείο δεν έχει τροποποιηθεί")
    else:
        print("Το αρχείο έχει αλλοιωθεί")

#Δημιουργία ονόματος αρχείου hash
def createHashFileName(giveFile,algorithm):
    #Δημιουργία ονόματος αρχείου hash με βάση το όνομα του αρχείου και τον αλγόριθμο που χρησιμοποιήθηκε
    hashFileName=f"{giveFile}_{algorithm}.hash"
    return hashFileName

#Αποθήκευση των hash σε αρχείο .hash αλλα και την προσθήκη Salt
def saveHash(hashFile,salt,hashValue):
   
   with open(hashFile,"w") as f:
     f.write(salt.hex()+"\n")
     f.write(hashValue+"\n")
     f.write("line 1: Salt \n")
     f.write("line 2: Salt+Hash \n")

   print(f"Το hash αποθηκεύτηκε στο αρχείο {hashFile}")

#Το menu επιλογών για τον χρήστη
def menu():

    clear_screen()
    print("\n" + "="*75)
    print("!!! ΠΡΟΣΟΧΗ: Όλες οι επιλογές απαιτούν ταυτοποίηση με 2FA !!!")
    print("!!! Εάν θες να αποφύγεις την επαναληπτική ταυτοποίηση 2FA !!!")
    print("!!! Επίλεξε την επιλογή (4) για μόνιμη ταυτοποίηση με 2FA !!!")
    print("\n" + "="*75)
    print("        ΜΕΝΟΥ ΕΠΙΛΟΓΩΝ")
    print("="*75)
    print("1. Υπολογισμός Hash")
    print("2. Έλεγχος Ακεραιότητας")
    print("3. Υπολογισμός Εντροπίας")
    print("4. Έλεγχος ταυτότητας με 2FA")
    print("5. Έξοδος")
    print("="*75)

#Το menu επιλογών για τον χρήστη για να επιλέξει τον αλγόριθμο που θέλει να χρησιμοποιήσει
def menu_algorithms():
    
    clear_screen()
    print("\n" + "="*30)
    print("  ΜΕΝΟΥ ΕΠΙΛΟΓΩΝ ΑΛΓΟΡΙΘΜΟΥ")
    print("="*30)
    print("1. MD5 hash")
    print("2. SHA256 hash")
    print("3. SHA3 hash")
    print("4. Διπλό SHA256 hash")
    print("5. Όλα τα hash")
    print("-"*30)

#Το menu επιλογών για τον χρήστη για να επιλέξει ποιο hash θέλει να χρησιμοποιήσει για τον έλεγχο ακεραιότητας του αρχείου
def menu_integrityCheck(hashFiles):

    clear_screen()
    print("="*30)
    print("   ΔΙΑΘΕΣΙΜΑ ΑΡΧΕΙΑ HASH ")
    print("  ΓΙΑ ΕΛΕΓΧΟ ΑΚΕΡΑΙΟΤΗΤΑΣ:")
    print("="*30)
    for f in hashFiles:
        print(f"-->{f}")
    print("\n" + "="*30)
    print("  ΜΕΝΟΥ ΕΠΙΛΟΓΩΝ ΑΛΓΟΡΙΘΜΟΥ")
    print("    ΈΛΕΓΧΟΣ ΑΚΕΡΑΙΟΤΗΤΑΣ")
    print("="*30)
    print("1. md5.hash")
    print("2. sha256.hash")
    print("3. sha3.hash")
    print("4. sha256double.hash")
    print("5. Όλα τα hash")
    print("-"*30)

#Είσοδος αρχείου και έλεγχος αν υπάρχει
while True:
 try:
    print("\n" + "-"*75)
    print("Δώσε όνομα αρχείου σε μορφή όνομα_αρχείου.μορφη_αρχειου (π.χ. example.txt)")
    print("-"*75)
    giveFile=input("--->")
    with open(giveFile,"rb") as f:
     readFile=f.read()
    break
 except FileNotFoundError:
    print("Το αρχείο δεν βρέθηκε, δοκίμασε ξανά")
    continue

#Δημιουργία ονομάτων αρχείων hash με βάση το όνομα του αρχείου που έδωσε ο χρήστης
#(Αυτο γίνεται για να μην υπάρχει σύγχυση με τα ονόματα των αρχείων hash σε περιπτωση 
# που ο χρηστης εχει πολλα αρχεία .txt στον ίδιο φάκελο)
nameWithoutTxt=os.path.splitext(giveFile)[0]
file_md5=f"{nameWithoutTxt}_md5.hash"
file_sha256=f"{nameWithoutTxt}_sha256.hash"
file_sha3= f"{nameWithoutTxt}_sha3.hash"
file_sha256double=f"{nameWithoutTxt}_sha256double.hash"

check=False
while True:

    menu()
    epilogi=int(input("Επίλεξε  (1-5):"))

    #Επιλογή υπολογισμού hash
    if epilogi==1:
        
        if check or auth_2FA():
            input("\nΠατήστε Enter για συνέχεια...")
            menu_algorithms()
            #Επιλογή αλγορίθμου και υπολογισμός hash
            algSelect=int(input("--->"))

            #υπολογισμός MD5 hash
            if algSelect==1:
                
                #Υπολογισμός του MD5 hash του αρχείου και προσθήκη salt χρησιμοποιώντας τη βιβλιοθήκη hashlib και αποθήκευση του αποτελέσματος σε μεταβλητή
                salt,readFileSalted=add_Salt(giveFile)
                hashMD5=hashlib.md5(readFileSalted).hexdigest()
                print(f"Το MD5 hash του {giveFile} είναι:{hashMD5}")
                saveHash(file_md5,salt,hashMD5)
                input("\nΠατήστε Enter για συνέχεια...")

                

            #υπολογισμός SHA256 hash
            elif algSelect==2:
              
                #Υπολογισμός του SHA256 hash του αρχείου και προσθήκη salt χρησιμοποιώντας τη βιβλιοθήκη hashlib και αποθήκευση του αποτελέσματος σε μεταβλητή
                salt,readFileSalted=add_Salt(giveFile)
                hashSHA256=hashlib.sha256(readFileSalted).hexdigest()
                print(f"Το SHA256 hash του {giveFile} είναι:{hashSHA256}")
                saveHash(file_sha256,salt,hashSHA256)
                input("\nΠατήστε Enter για συνέχεια...")

                

            #υπολογισμός SHA3 hash
            elif algSelect==3:

                #Υπολογισμός του SHA3 hash του αρχείου και προσθήκη salt χρησιμοποιώντας τη βιβλιοθήκη hashlib και αποθήκευση του αποτελέσματος σε μεταβλητή
                salt,readFileSalted=add_Salt(giveFile)
                hashSHA3=hashlib.sha3_256(readFileSalted).hexdigest()
                print(f"Το SHA3 hash του {giveFile} είναι:{hashSHA3}")  
                saveHash(file_sha3,salt,hashSHA3)
                input("\nΠατήστε Enter για συνέχεια...")

                
            elif algSelect==4:
            
                #Υπολογισμός του διπλού SHA256 hash του αρχείου και προσθήκη salt χρησιμοποιώντας τη βιβλιοθήκη hashlib και αποθήκευση του αποτελέσματος σε μεταβλητή
                salt,readFileSalted=add_Salt(giveFile)
                hashSHA256=hashlib.sha256(readFileSalted).hexdigest()
                hashSHA256double=hashlib.sha256(hashSHA256.encode()).hexdigest()
                print(f"Το διπλό SHA256 hash του {giveFile} είναι:{hashSHA256double}")
                saveHash(file_sha256double,salt,hashSHA256double)
                input("\nΠατήστε Enter για συνέχεια...")

                
            #υπολογισμός όλων των hash
            elif algSelect==5:

                salt,readFileSalted=add_Salt(giveFile)
                hashMD5=hashlib.md5(readFileSalted).hexdigest()
                print(f"Το MD5 hash του {giveFile} είναι:{hashMD5}")
                saveHash(file_md5,salt,hashMD5)

                salt,readFileSalted=add_Salt(giveFile)
                hashSHA256=hashlib.sha256(readFileSalted).hexdigest()
                print(f"Το SHA256 hash του {giveFile} είναι:{hashSHA256}")
                saveHash(file_sha256,salt,hashSHA256)

                salt,readFileSalted=add_Salt(giveFile)
                hashSHA3=hashlib.sha3_256(readFileSalted).hexdigest()
                print(f"Το SHA3 hash του {giveFile} είναι:{hashSHA3}")  
                saveHash(file_sha3,salt,hashSHA3)

                salt,readFileSalted=add_Salt(giveFile)
                hashSHA256=hashlib.sha256(readFileSalted).hexdigest()
                hashSHA256double=hashlib.sha256(hashSHA256.encode()).hexdigest()
                print(f"Το διπλό SHA256 hash του {giveFile} είναι:{hashSHA256double}")
                saveHash(file_sha256double,salt,hashSHA256double)
                input("\nΠατήστε Enter για συνέχεια...")


                
                
            #Ελεγχος για μη έγκυρη επιλογή αλγορίθμου
            else:

                print("Μη έγκυρη επιλογή, υπολογίστε ξανά")

                algSelect=int(input("--->"))
        else:
            print("Η ταυτοποίηση με 2FA απέτυχε, δεν μπορείς να υπολογίσεις hash.")
            input("\nΠατήστε Enter για να ξαναπροσπαθήσεις...")
            continue
    
    #Επιλογή ελέγχου ακεραιότητας
    elif epilogi==2:
        
        if check or auth_2FA():
            input("\nΠατήστε Enter για συνέχεια...")
            #Έλεγχος για αρχεία hash στον τρέχοντα φάκελο 
            hashFiles = [f for f in os.listdir() if f.endswith(".hash")]

            #Αν υπάρχουν αρχεία hash εμφανίζουμε το menu επιλογών για έλεγχο ακεραιότητας 
            # και ζητάμε από τον χρήστη να επιλέξει ποιο hash θέλει να χρησιμοποιήσει για τον έλεγχο ακεραιότητας του αρχείου.
            if hashFiles:

                menu_integrityCheck(hashFiles)
                hashFileSelect=int(input())

                #Ξανα ανοίγουμε το αρχείο σε περίπτωση που ο χρήστης έχει επιλέξει έλεγχο ακεραιότητας την στιγμή που τρέχει το πρόγραμμα και έχει τροποποιήσει το αρχείο,
                # έτσι ώστε να διαβάσουμε το νέο περιεχόμενο του αρχείου και να υπολογίσουμε τα νέα hash για τον έλεγχο ακεραιότητας
                with open(giveFile, "rb") as f:
                 readFile = f.read()

                

                if hashFileSelect==1:
                    
                    hash_integrityCheck(file_md5,giveFile,"md5")
                    input("\nΠατήστε Enter για συνέχεια...")


                elif hashFileSelect==2:

                    #Υπολογισμός του τρέχοντος SHA256 hash του αρχείου και ελεγχος της ακεραιότητας συγκρίνοντας το τρέχον hash με το αποθηκευμένο hash
                    hash_integrityCheck(file_sha256,giveFile,"sha256")
                    input("\nΠατήστε Enter για συνέχεια...")


                elif hashFileSelect==3:

                    #Υπολογισμός του τρέχοντος SHA3 hash του αρχείου και ελεγχος της ακεραιότητας συγκρίνοντας το τρέχον hash με το αποθηκευμένο hash
                    hash_integrityCheck(file_sha3,giveFile,"sha3")
                    input("\nΠατήστε Enter για συνέχεια...")


                elif hashFileSelect==4:

                    #Υπολογισμός του τρέχοντος διπλού SHA256 hash του αρχείου και ελεγχος της ακεραιότητας συγκρίνοντας το τρέχον hash με το αποθηκευμένο hash
                    hash_integrityCheck(file_sha256double,giveFile,"sha256double")
                    input("\nΠατήστε Enter για συνέχεια...")


                elif hashFileSelect==5:

                    #Υπολογισμός όλων των τρέχοντων hash του αρχείου και ελεγχος της ακεραιότητας συγκρίνοντας τα τρέχοντα hash με τα αποθηκευμένα hash
        
                    hash_integrityCheck(file_md5,giveFile,"md5")

                    hash_integrityCheck(file_sha256,giveFile,"sha256")

                    hash_integrityCheck(file_sha3,giveFile,"sha3") 

                    hash_integrityCheck(file_sha256double,giveFile,"sha256double")
                    input("\nΠατήστε Enter για συνέχεια...")


                #Ελεγχος για μη έγκυρη επιλογή αλγορίθμου
                else:

                    print("Μη έγκυρη επιλογή, δοκίμασε ξανά.")
                    hashFileSelect=int(input("--->"))
                    
            else:
                print("Δεν υπάρχουν αρχεία hash για έλεγχο ακεραιότητας, υπολόγισε πρώτα ένα hash.")
                continue
        else:
            print("Η ταυτοποίηση με 2FA απέτυχε, δεν μπορείς να κάνεις έλεγχο ακεραιότητας.")
            input("\nΠατήστε Enter για να ξαναπροσπαθήσεις...")
            continue

    elif epilogi==3:
        
        if check or auth_2FA():
            input("\nΠατήστε Enter για συνέχεια...")
            #Υπολογισμός της εντροπίας του αρχείου και εμφάνιση του αποτελέσματος
            entropy=calculate_entyropy(giveFile)
            print(f"Η εντροπία του {giveFile} είναι: {entropy:.2f} ")
            input("\nΠατήστε Enter για συνέχεια...")

        else:
            print("Η ταυτοποίηση με 2FA απέτυχε, δεν μπορείς να υπολογίσεις την εντροπία.")
            input("\nΠατήστε Enter για συνέχεια...")
            continue    
    
    elif epilogi==4:
        #Έλεγχος ταυτότητας με 2FA για μόνιμη ταυτοποίηση και αποθήκευση της πληροφορίας σε μεταβλητή 
        #ώστε να μην χρειάζεται ο χρήστης να κάνει επαναληπτική ταυτοποίηση με 2FA για κάθε επιλογή στο menu
        print("Επίλεξες έλεγχο ταυτότητας με 2FA")
        if auth_2FA():
            check=True
            input("\nΠατήστε Enter για συνέχεια...")
        else:
            check=False
            input("\nΠατήστε Enter και ξανα προσπαθήστε...")


    #Επιλογή έξοδος από το πρόγραμμα
    elif epilogi==5:
        print("Έξοδος από το πρόγραμμα.")
        break

    #Ελεγχος για μη έγκυρη επιλογή στο menu
    else:
        print("Μη έγκυρη επιλογή, δοκίμασε ξανά.")
        input("\nΠατήστε Enter για να εισάγετε σωστή επιλογή...")
        continue
       

 