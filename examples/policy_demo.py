import os
import yaml
from deadend.policy import PolicyLoader

# Create a sample YAML policy
sample_policy = """
version: "1.0"
mode: "enforce"

sentinel:
  enabled: true
  detectors:
    semantic_injection:
      enabled: true
      threshold: 0.90

warden:
  enabled: true
  allowed_tools: ["search", "calculator"]
  denied_patterns: ["rm -rf", "eval", "exec"]
  monitors:
    semantic_command:
      enabled: true

guardian:
  enabled: true
  redact_pii: true
"""

with open("deadend-policy.yaml", "w") as f:
    f.write(sample_policy)

print("Created deadend-policy.yaml")

# Load the policy
policy = PolicyLoader.load()

print("\nLoaded Policy Configuration:")
print(f"Mode: {policy.mode}")
print(f"Sentinel enabled: {policy.sentinel.enabled}")
print(f"Warden allowed tools: {policy.warden.allowed_tools}")
print(f"Warden denied patterns: {policy.warden.denied_patterns}")
print(f"Guardian redact PII: {policy.guardian.redact_pii}")

print("\nSemantic Injection Detector Config:")
sem_inj = policy.sentinel.detectors.get("semantic_injection")
if sem_inj:
    print(f"Enabled: {sem_inj.enabled}, Threshold: {sem_inj.threshold}")

# Clean up
os.remove("deadend-policy.yaml")
