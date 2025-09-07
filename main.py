from src.cluster_policy import main
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the SROS2 Policy Clustering")
    parser.add_argument("--policy_dir", type=str, default="./policies")
    parser.add_argument("--output_dir", type=str, default="./output")
    parser.add_argument("--threshold", type=float, default=0.8)
    args = parser.parse_args()
    
    main(args.policy_dir, args.output_dir, args.threshold)