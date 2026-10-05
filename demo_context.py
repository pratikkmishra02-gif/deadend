from deadend.context import ContextEngine

print("Initializing Context Engine...")
engine = ContextEngine()

print("\n--- Getting System Context for Llama 3.1 70B (Full Context) ---")
# Using a specific model to demonstrate how the context window adapts
context = engine.get_system_context(model="llama-3.1-70b", compact=False)
print(context[:500] + "...\n[TRUNCATED FOR DEMO]\n")

print("--- Getting System Context for smaller model (Compact Context) ---")
compact_context = engine.get_system_context(model="gemma-2-9b", compact=True)
print(compact_context[:500] + "...\n[TRUNCATED FOR DEMO]\n")

print("--- Querying the Wiki for 'prompt injection' ---")
articles = engine.query("prompt injection")
for a in articles[:3]:
    print(f"- {a.title} (Category: {a.category.value})")
