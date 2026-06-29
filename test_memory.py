import asyncio
import os
import cognee
from dotenv import load_dotenv

# Load your secret API keys
load_dotenv()

async def main():
    print("🧠 Resetting memory to clean state...")
    await cognee.forget(everything=True)

    print("📝 Step 1: Teaching Cognee security context...")
    # This automatically runs ingestion, chunks, and maps relationships in the background
    await cognee.remember("AuditTrail AI logs show Server-B is running outdated Apache version 2.4.41.")

    print("🔍 Step 2: Recalling from long-term graph memory...")
    # Cognee handles the smart semantic graph-routing for you
    results = await cognee.recall("What security issue does Server-B have?")
    
    print("\n--- Cognee Output Context ---")
    for result in results:
        print(result.text)

if __name__ == "__main__":
    asyncio.run(main())