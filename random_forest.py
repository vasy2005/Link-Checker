import numpy
import pandas as pd
from sklearn.impute import SimpleImputer
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from concurrent.futures import TimeoutError
from main import CheckURL
from enum import IntEnum
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

class ThreatLevel(IntEnum):
    UNKNOWN = 0
    CLEAN = 1
    SUSPICIOUS = 2
    MALICIOUS = 3

    def __str__(self):
        strings = {
            ThreatLevel.UNKNOWN: "Unknown",
            ThreatLevel.CLEAN: "Clean", 
            ThreatLevel.SUSPICIOUS: "Suspicious",
            ThreatLevel.MALICIOUS: "Malicious"
        }
        return strings[self]

class RandomForest:
    def __init__(self):
        self.__data_path = './malicious_phish.csv'
        self.__feature_names  = ['url_length', 'num_subdirs', 'num_digits', 'contains_ip_address', 'number_of_subdomains', 'has_login_keyword', 'is_shortened_url', 'domain_shannon_entropy', 'domain_age_days', 'domain_expiration_days', 'ttl', 'vt_malicious_ratio', 'vt_suspicious_ratio', 'vt_clean_ratio', 'vt_unknown_ratio', 'vt_times_submitted', 'vt_internal_trust_score', 'comm_votes_malicious', 'fox_status', 'fox_confidence', 'gsb_status', 'is_skeleton_different', 'levenshtein_distance']

    def setup_dataset(self):
        feature_names = self.__feature_names

        df = pd.read_csv(self.__data_path, header=None, skiprows = 1, names = ['url', 'type'])
        df = df.head(4000)

        mapping = {}
        mapping['benign'] = ThreatLevel.CLEAN
        mapping['malware'] = ThreatLevel.MALICIOUS
        mapping['phishing'] = ThreatLevel.MALICIOUS
        mapping['defacement'] = ThreatLevel.SUSPICIOUS
        df['type'] = df['type'].map(mapping)
        df.drop(df.columns[1], axis=1, inplace=True)

        df2 = pd.read_excel('my_data.xlsx', header=None, skiprows = 1, names = ['url', 'type', 'url_length', 'num_subdirs', 'num_digits', 'contains_ip_address', 'number_of_subdomains', 'has_login_keyword', 'is_shortened_url', 'domain_shannon_entropy', 'domain_age_days', 'domain_expiration_days', 'ttl', 'vt_malicious_ratio', 'vt_suspicious_ratio', 'vt_clean_ratio', 'vt_unknown_ratio', 'vt_times_submitted', 'vt_internal_trust_score', 'comm_votes_malicious', 'fox_status', 'fox_confidence', 'gsb_status', 'is_skeleton_different', 'levenshtein_distance'])
        df2.drop(df2.columns[1], axis=1, inplace=True)
        df_comb = pd.merge(left = df, right = df2, on = 'url', how='left')
        df = df_comb
        for feature in feature_names:
            df.loc[1000:, feature] = 0.0
        # cols = feature_names
        # df[cols] = df[cols].astype(float)
        try:
            with ThreadPoolExecutor(max_workers=12) as executor:
                futures = []
                df_ultimele = df.tail(3000)

                # Iterează peste acest subset
                for row in df_ultimele.itertuples(index=True):
                    object = CheckURL()
                    futures.append(executor.submit(object.run, row.url))

                for future in as_completed(futures):
                    try:
                        feature_dict, url = future.result()
                        feature_dict = {k: float(v) if isinstance(v, bool) else v for k, v in feature_dict.items()}
                        print(feature_dict)
                        df.loc[df['url'] == url, feature_dict.keys()] = feature_dict.values()
                    except Exception as e:
                        pass
        except Exception as e:
            pass

        df.to_excel('my_data3.xlsx', index=False)

        print(df)

    def build_rfc(self):
        feature_names = self.__feature_names

        df2 = pd.read_excel('my_data3.xlsx', header=None, skiprows = 1, names = ['url', 'type', 'url_length', 'num_subdirs', 'num_digits', 'contains_ip_address', 'number_of_subdomains', 'has_login_keyword', 'is_shortened_url', 'domain_shannon_entropy', 'domain_age_days', 'domain_expiration_days', 'ttl', 'vt_malicious_ratio', 'vt_suspicious_ratio', 'vt_clean_ratio', 'vt_unknown_ratio', 'vt_times_submitted', 'vt_internal_trust_score', 'comm_votes_malicious', 'fox_status', 'fox_confidence', 'gsb_status', 'is_skeleton_different', 'levenshtein_distance'])
        df = pd.read_csv(self.__data_path, header=None, skiprows = 1, names = ['url', 'type'])
        df2['levenshtein_distance'] = 0
        X = df2.iloc[:, 2:len(feature_names)+2]
        # print(X)

        mapping = {}
        mapping['benign'] = ThreatLevel.CLEAN
        mapping['malware'] = ThreatLevel.MALICIOUS
        mapping['phishing'] = ThreatLevel.MALICIOUS
        mapping['defacement'] = ThreatLevel.SUSPICIOUS
        df['type'] = df['type'].map(mapping)
        y = df.iloc[:4000, 1].fillna(0).values.reshape(-1,1)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, stratify=y)
        rf = RandomForestClassifier(class_weight='balanced')
        rf.fit(X_train, y_train)
        print(y)
        print(X)
        return

        y_pred = rf.predict(X_test)
        print(rf.score(X_test, y_test))
        print(classification_report(y_test, y_pred))

        joblib.dump(rf, 'random_forest_url_model.joblib')


if __name__ == '__main__':
    rf = RandomForest()
    rf.build_rfc()