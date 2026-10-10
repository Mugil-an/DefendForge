import sys
import os
import numpy as np
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))
from blue_agent.detection.isolation_forest import IsolationForestDetector

def main():
    X_normal = np.zeros((500, 24))
    
    # Feature rough indices based on dict order from logs
    # We just put some realistic variance
    X_normal[:, 0] = np.random.uniform(100, 1000, 500) # request_size
    X_normal[:, 1] = np.random.uniform(100, 5000, 500) # response_size
    X_normal[:, 2] = 200 # response_code
    X_normal[:, 3] = np.random.uniform(1, 50, 500) # latency
    X_normal[:, 12:16] = 0 # has_sql, script, traversal, command

    detector = IsolationForestDetector()
    detector.fit(X_normal)
    detector.save("models/isolation_forest.joblib")
    print("Fixed model saved")

if __name__ == "__main__":
    main()
