import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
df = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt", header=None)
columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
'root_shell','su_attempted','num_root','num_file_creations','num_shells',
'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
'label','difficulty']

df.columns = columns
df = df.drop('difficulty', axis=1)

le = LabelEncoder()
df['protocol_type'] = le.fit_transform(df['protocol_type'])
df['service'] = le.fit_transform(df['service'])
df['flag'] = le.fit_transform(df['flag'])
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

print(df.shape)
print(df.head())
X = df.drop('label', axis=1)
y = df['label']

model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X)
predictions = model.predict(X)
predictions = [0 if p == 1 else 1 for p in predictions]

print("\n--- MODEL RESULTS ---")
print(classification_report(y, predictions, target_names=['Normal', 'Attack']))
import matplotlib.pyplot as plt

labels = ['Normal', 'Attack']
actual_counts = [sum(y == 0), sum(y == 1)]
predicted_counts = [predictions.count(0), predictions.count(1)]

x = range(len(labels))
plt.figure(figsize=(8, 5))
plt.bar(x, actual_counts, width=0.4, label='Actual', align='center')
plt.bar([i + 0.4 for i in x], predicted_counts, width=0.4, label='Predicted', align='center')
plt.xticks([i + 0.2 for i in x], labels)
plt.title('Actual vs Predicted — Network Intrusion Detection')
plt.ylabel('Count')
plt.legend()
plt.tight_layout()
plt.savefig('results.png')
print("Graph saved as results.png")