import sys
import os
import numpy as np
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))
from blue_agent.detection.random_forest import RandomForestDetector

def main():
    np.random.seed(42)
    # Generate 1000 samples (500 benign, 500 attack)
    X = np.zeros((1000, 24))
    y = np.zeros(1000)
    
    # Benign: features 12:16 (has_sql, script, traversal, command) are 0
    # Attack: set y=1 and randomly set one of 12:16 to 1
    
    for i in range(1000):
        # request_size, response_size, latency
        X[i, 0] = np.random.uniform(100, 1000)
        X[i, 1] = np.random.uniform(100, 5000)
        X[i, 3] = np.random.uniform(1, 50)
        
        # request_rate, unique_endpoints
        X[i, 4] = np.random.uniform(1, 10)
        X[i, 6] = np.random.uniform(1, 5)
        
        is_attack = (i >= 500)
        if is_attack:
            y[i] = 1
            # Randomly set one of the malicious regex features to 1
            malicious_feat = np.random.choice([12, 13, 14, 15])
            X[i, malicious_feat] = 1.0
            
            # Maybe 4xx response code
            X[i, 2] = 403
            X[i, 22] = 1.0 # response_code_is_4xx
        else:
            X[i, 2] = 200
            X[i, 22] = 0.0

    detector = RandomForestDetector()
    detector.fit(X, y)
    
    os.makedirs("models", exist_ok=True)
    detector.save("models/random_forest_24.joblib")
    print("Random forest 24-feature model saved to models/random_forest_24.joblib")

if __name__ == "__main__":
    main()
