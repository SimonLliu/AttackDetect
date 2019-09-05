# -*- coding: utf-8 -*-
"""
Created on Mon Dec 25 08:10:39 2017

@author: Simon
"""


import urllib2
from math import sqrt, fabs, exp
import matplotlib.pyplot as plot
from sklearn.linear_model import enet_path
from sklearn.metrics import accuracy_score, confusion_matrix, roc_curve
from sklearn.cross_validation import train_test_split
from sklearn import ensemble
import numpy
import datetime
from sklearn import svm

starttime = datetime.datetime.now()
#target_url = "https://archive.ics.uci.edu/ml/machine-learning-databases/glass/glass.data"
target_url = "file:/D:/MyPaper/KDD99/kddcup01.csv"

req = urllib2.Request(target_url)
data0 = urllib2.urlopen(req)
data = data0.readlines()
#arrange data into list for labels and list of lists for attributes
xList = []

for i in range(0,800):
    for line in data[500*i:500*(i+1)]:
    #split on comma
        row = line.strip().split(",")
        xList.append(row)
glassNames = numpy.array(['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_hot_login', 'is_guest_login' ,'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_srv_port_rate', 'dst_host_srv_diff_host_rate' ,'dst_host_serror_rate' ,'dst_host_srv_serror_rate','dst_host_reoor_rate' ,'dst_host_srv_rerror_rate' ,'type'])
xNum = []
labels = []
k = 0
for k in range(0,800):
    for row in xList[500*k:500*(k+1)]:
       labels.append(row.pop())
       l = len(row)
       #eliminate ID
       if row[1]=='tcp': row[1]=0
       if row[1]=='udp': row[1]=1
       if row[1]=='icmp': row[1]=2
       if row[2]=='aol': row[2]=0
       if row[2]=='auth': row[2]=1
       if row[2]=='bgp': row[2]=2
       if row[2]=='courier': row[2]=3
       if row[2]=='csnet_ns': row[2]=4        
       if row[2]=='ctf': row[2]=5
       if row[2]=='daytime': row[2]=6
       if row[2]=='discard': row[2]=7
       if row[2]=='domain': row[2]=8
       if row[2]=='domain_u': row[2]=9
       if row[2]=='echo': row[2]=10
       if row[2]=='eco_i': row[2]=11
       if row[2]=='ecr_i': row[2]=12
       if row[2]=='efs': row[2]=13
       if row[2]=='exec': row[2]=14
       if row[2]=='finger': row[2]=15
       if row[2]=='ftp': row[2]=16
       if row[2]=='ftp_data': row[2]=17
       if row[2]=='gopher': row[2]=18   
       if row[2]=='harvest': row[2]=19 
       if row[2]=='hostnames': row[2]=20 
       if row[2]=='http': row[2]=21 
       if row[2]=='http_2784': row[2]=22 
       if row[2]=='http_443': row[2]=23 
       if row[2]=='http_8001': row[2]=24 
       if row[2]=='imap4': row[2]=25 
       if row[2]=='IRC': row[2]=26 
       if row[2]=='iso_tsap': row[2]=27 
       if row[2]=='klogin': row[2]=28 
       if row[2]=='kshell': row[2]=29 
       if row[2]=='ldap': row[2]=30 
       if row[2]=='link': row[2]=31 
       if row[2]=='login': row[2]=32 
       if row[2]=='mtp': row[2]=33 
       if row[2]=='name': row[2]=34 
       if row[2]=='netbios_dgm': row[2]=35 
       if row[2]=='netbios_ns': row[2]=36 
       if row[2]=='netbios_ssn': row[2]=37 
       if row[2]=='netstat': row[2]=38 
       if row[2]=='nnsp': row[2]=39 
       if row[2]=='nntp': row[2]=40 
       if row[2]=='ntp_u': row[2]=41 
       if row[2]=='other': row[2]=42 
       if row[2]=='pm_dump': row[2]=43 
       if row[2]=='pop_2': row[2]=44 
       if row[2]=='pop_3': row[2]=45 
       if row[2]=='printer': row[2]=46 
       if row[2]=='private': row[2]=47 
       if row[2]=='red_i': row[2]=48 
       if row[2]=='remote_job': row[2]=49 
       if row[2]=='rje': row[2]=50 
       if row[2]=='shell': row[2]=51 
       if row[2]=='smtp': row[2]=52 
       if row[2]=='sql_net': row[2]=53 
       if row[2]=='ssh': row[2]=54 
       if row[2]=='sunrpc': row[2]=55 
       if row[2]=='supdup': row[2]=56 
       if row[2]=='systat': row[2]=57 
       if row[2]=='telnet': row[2]=58 
       if row[2]=='tftp_u': row[2]=59 
       if row[2]=='tim_i': row[2]=60 
       if row[2]=='time': row[2]=61 
       if row[2]=='urh_i': row[2]=62 
       if row[2]=='urp_i': row[2]=63 
       if row[2]=='uucp': row[2]=64
       if row[2]=='uucp_path': row[2]=65 
       if row[2]=='vmnet': row[2]=66 
       if row[2]=='whois': row[2]=67 
       if row[2]=='X11': row[2]=68
       if row[2]=='Z39_50': row[2]=69 
       if row[3]=='OTH': row[3]=0
       if row[3]=='REJ': row[3]=1 
       if row[3]=='RSTO': row[3]=2 
       if row[3]=='RSTOS0': row[3]=3 
       if row[3]=='RSTR': row[3]=4 
       if row[3]=='S0': row[3]=5 
       if row[3]=='S1': row[3]=6 
       if row[3]=='S2': row[3]=7 
       if row[3]=='S3': row[3]=8 
       if row[3]=='SF': row[3]=9
       if row[3]=='SH': row[3]=10 
       attrRow = [float(row[i]) for i in range(0, l-1)]
       xNum.append(attrRow)
#for i in range(len(xNum)):
#    xNum[i]=xNum[i][0:35]
for i in range(len(xNum)):
    xNum[i]=[xNum[i][1],xNum[i][2],xNum[i][3],xNum[i][4],xNum[i][5],xNum[i][22],xNum[i][23],xNum[i][24],xNum[i][35]]
nrows = len(xNum)
ncols = len(xNum[1])
#print nrows, ncols
#print labels
newLabels = []
labelSet = set(labels)
labelList = list(labelSet)
labelList.sort()
#print labelList
nlabels = len(labelList)
for l in labels:
    index = labelList.index(l)
    newLabels.append(index)
#print newLabels
#print newLabels
#xTemp = [xNum[i] for i in range(nrows) if newLabels[i] == 0]
#yTemp = [newLabels[i] for i in range(nrows) if newLabels[i] == 0]
#xTrain, xTest, yTrain, yTest = train_test_split(xTemp, yTemp, test_size=0.30, random_state=531)
xTemp0 = [xNum[i] for i in range(nrows) if newLabels[i] == 0]
xTemp = [xTemp0[i*10] for i in range(len(xTemp0)/10)]
yTemp0 = [newLabels[i] for i in range(nrows) if newLabels[i] == 0]
yTemp = [yTemp0[i*10] for i in range(len(yTemp0)/10)]
#print xTemp
xTrain, xTest, yTrain, yTest = train_test_split(xTemp, yTemp, test_size=0.30, random_state=531)
print len(xTrain), len(yTest)
for iLabel in range(1, len(labelList)):
    #segregate x and y according to labels
    xTemp = [xNum[i] for i in range(nrows) if newLabels[i] == iLabel]
    yTemp = [newLabels[i] for i in range(nrows) if newLabels[i] == iLabel]
    #xTemp = [xTemp0[i*3] for i in range(len(xTemp0)/3)]
    #yTemp = [yTemp0[i*3] for i in range(len(yTemp0)/3)]
    #print yTemp0
    #form train and test sets on segregated subset of examples
    xTrainTemp, xTestTemp, yTrainTemp, yTestTemp = train_test_split(xTemp, yTemp, test_size=0.30, random_state=531)
    #print xTrainTemp
    #accumulate
    xTrain = numpy.append(xTrain, xTrainTemp, axis=0); xTest = numpy.append(xTest, xTestTemp, axis=0)
    yTrain = numpy.append(yTrain, yTrainTemp, axis=0); yTest = numpy.append(yTest, yTestTemp, axis=0)
print len(xTrain) 
missCLassError = []
#nTreeList = range(50, 70, 1)
#for iTrees in nTreeList:
#    maxFeat  = 8 #try tweaking
#    attackRFModel = ensemble.RandomForestClassifier(n_estimators=iTrees, max_depth=depth, max_features=maxFeat,
#                                                 oob_score=False, random_state=531)

#    attackRFModel.fit(xTrain,yTrain)

clf = svm.SVC(gamma=0.0005, C=10000.)  
clf.fit(xTrain,yTrain)
    #Accumulate auc on test set
#   prediction = attackRFModel.predict(xTest)
prediction = clf.predict(xTest)
correct = accuracy_score(yTest, prediction)

missCLassError.append(1.0 - correct)

print("Missclassification Error" )
print(missCLassError[-1])

#generate confusion matrix
pList = prediction.tolist()
confusionMat = confusion_matrix(yTest, pList)
print('')
print("Confusion Matrix")
print(confusionMat)



#plot training and test errors vs number of trees in ensemble
#plot.plot(nTreeList, missCLassError)
#plot.xlabel('Number of Trees in Ensemble')
#plot.ylabel('Missclassification Error Rate')
#plot.ylim([0.0, 1.1*max(mseOob)])
plot.show()

# Plot feature importance
#featureImportance = attackRFModel.feature_importances_

# normalize by max importance
#featureImportance = featureImportance / featureImportance.max()

#plot variable importance
#idxSorted = numpy.argsort(featureImportance)
#barPos = numpy.arange(idxSorted.shape[0]) + .5
#plot.barh(barPos, featureImportance[idxSorted], align='center')
#plot.yticks(barPos, glassNames[idxSorted])
#plot.xlabel('Variable Importance')
#plot.show()
endtime = datetime.datetime.now()
print (endtime - starttime).seconds
# Printed Output:
# Missclassification Error
# 0.227272727273
#
# Confusion Matrix
# [[17  1  2  0  0  1]
#  [ 2 18  1  2  0  0]
#  [ 3  0  3  0  0  0]
#  [ 0  0  0  4  0  0]
#  [ 0  1  0  0  2  0]
#  [ 0  2  0  0  0  7]]
