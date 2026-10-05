"""
Script to train the PPO (Reinforcement Learning) policy for Blue Agent.
"""

import logging
from blue_agent.logging_cfg import setup_logging
from blue_agent.decision.ppo_policy import PPOPolicy
from blue_agent.config import settings

def main():
    setup_logging()
    log = logging.getLogger("train_rl")
    
    log.info("Initializing PPO Policy for training...")
    policy = PPOPolicy()
    
    # Train the policy. The total timesteps will default to settings.ppo.total_timesteps (100,000)
    log.info(f"Starting training for {settings.ppo.total_timesteps} timesteps...")
    policy.train()
    
    # Save the trained model to the default configured path
    log.info(f"Saving model to {settings.ppo.model_path}...")
    policy.save()
    
    log.info("Training complete and model saved successfully.")

if __name__ == "__main__":
    main()
