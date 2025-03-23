from main import SecuritySimulationSystem
from simulation.attack_simulator import AttackConfig
import time

def main():
    # Initialize the security simulation system
    system = SecuritySimulationSystem()
    
    try:
        # Initialize and start the system
        system.initialize()
        system.iot_simulation.start_simulation()
        
        # Create botnet attack configuration targeting smart camera and lock
        attack_config = AttackConfig(
            attack_type="botnet",
            targets=["camera_01", "lock_01"],
            duration=300  # 5 minutes attack duration
        )
        
        # Launch the attack
        print("Launching botnet attack...")
        attack_id = system.simulate_attack(attack_config)
        
        # Monitor the attack for its duration
        start_time = time.time()
        while time.time() - start_time < attack_config.duration:
            # Get attack status
            status = system.attack_simulator.get_attack_status(attack_id)
            print(f"\nAttack Status: {status['status']}")
            
            if status['events']:
                print("Current Events:")
                for event in status['events']:
                    print(f"- Phase: {event['phase']}: {event['description']}")
            
            time.sleep(10)  # Update every 10 seconds
        
        # Stop the attack
        print("\nStopping attack...")
        system.stop_attack(attack_id)
        
        # Let the system process final events
        time.sleep(5)
        
        # Shutdown the system
        system.shutdown()
        print("\nSimulation completed successfully")
        
    except KeyboardInterrupt:
        print("\nReceived shutdown signal")
        system.shutdown()
    except Exception as e:
        print(f"\nError during simulation: {str(e)}")
        system.shutdown()
        raise

if __name__ == "__main__":
    main()