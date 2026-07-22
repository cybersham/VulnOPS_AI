import os 
import time
import chromadb
from google import genai
from google.genai.types import EmbedContentConfig
from sqlalchemy.orm import Session
import models
import os
chroma_path = os.getenv("CHROMA_PATH", "./chroma_data")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY)


chroma_client = chromadb.PersistentClient(path=chroma_path)
collection = chroma_client.get_or_create_collection(name="cve_descriptions")

def embed_and_store_cves(db: Session) -> dict:
    cves = db.query(models.CVE).all()

    stored_count = 0
    errors = []

    for cve in cves:
        existing = collection.get(ids=[cve.cve_id])
        if existing["ids"]:
            print(f"SKIP (already embedded): {cve.cve_id}")
            continue

        try:
            print(f"Embedding: {cve.cve_id}...")
            response = client.models.embed_content(
                model="gemini-embedding-001",
                contents=cve.description,
                config=EmbedContentConfig(task_type="RETRIEVAL_DOCUMENT")
            )
            embedding_vector = response.embeddings[0].values

            collection.add(
                ids=[cve.cve_id],
                embeddings=[embedding_vector],
                documents=[cve.description],
                metadatas=[{
                    "cve_id": cve.cve_id,
                    "severity": cve.severity or "UNKNOWN",
                    "cvss_score": cve.cvss_score if cve.cvss_score is not None else -1,
                    "is_kev": cve.is_kev
                }]
            )
            print(f"SUCCESS: {cve.cve_id}")
            stored_count += 1

        except Exception as e:
            print(f"FAILED: {cve.cve_id} — {str(e)}")
            errors.append({"cve_id": cve.cve_id, "error": str(e)})

        time.sleep(4)

    return {"total_cves": len(cves), "newly_embedded": stored_count, "errors": errors}



# def query_vulnerabilities_semantic(question: str, n_results: int=5) -> dict:
#      # Step 1: embed the user's question (note: RETRIEVAL_QUERY, not RETRIEVAL_DOCUMENT)
#      query_embedding_response = client.models.embed_content(
#          model="gemini-embedding-001",
#          contents=question,
#          config=EmbedContentConfig(task_type="RETRIEVAL_QUERY")
#      )
    
#      query_vector = query_embedding_response.embeddings[0].values

#      # Step 2: search Chroma for the closest matching CVE descriptions
#      results=collection.query(
#           query_embeddings=[query_vector],
#           n_results=n_results

#      )

#      matched_docs = results["documents"][0]
#      matched_metadata = results["metadatas"][0]

#      if not matched_docs:
#          return{"answer" : "No relevant vulnerabilities found." , "sources": []}
     
#     # Step 3: build context from retrieved CVEs
#      context_lines =[]
#      for doc, meta in zip(matched_docs, matched_metadata):
#         cvss_display = "not yet scored by NVD" if meta['cvss_score'] == -1 else meta['cvss_score']
#         context_lines.append(
#         f"- {meta['cve_id']} ({meta['severity']}, CVSS {cvss_display}): {doc}"
#     )

#      context = "\n".join(context_lines)

#      # Step 4: ask Gemini to answer using only this retrieved context

#      prompt =  f"""You are a vulnerability management assistant. Answer the user's question
# using ONLY the vulnerability data provided below. If the data doesn't contain relevant
# information to answer the question, say so clearly.

# Vulnerability data:
# {context}

# Question: {question}

# Answer:"""
#      response = client.models.generate_content(
#          model="gemini-3.5-flash",
#          contents=prompt

#      )
     
#      return{
#          "answer": response.text,
#          "sources": [meta["cve_id"] for meta in matched_metadata]
#      }




import re

def query_vulnerabilities_semantic(question: str, n_results: int = 5) -> dict:
    # Check if the question contains an exact CVE ID — if so, fetch it directly
    cve_match = re.search(r"CVE-\d{4}-\d+", question, re.IGNORECASE)

    if cve_match:
        cve_id = cve_match.group(0).upper()
        try:
            exact_result = collection.get(ids=[cve_id], include=["documents", "metadatas"])
            if exact_result["ids"]:
                doc = exact_result["documents"][0]
                meta = exact_result["metadatas"][0]
                context = f"- {meta['cve_id']} ({meta['severity']}, CVSS {meta['cvss_score']}): {doc}"

                prompt = f"""You are a vulnerability management assistant. Answer the user's
question using ONLY the vulnerability data provided below.

Vulnerability data:
{context}

Question: {question}

Answer:"""

                response = client.models.generate_content(
                    model="gemini-3.5-flash",
                    contents=prompt
                )
                return {"answer": response.text, "sources": [cve_id]}
        except Exception:
            pass  # if exact lookup fails for any reason, fall through to semantic search below

    # Fall back to semantic search for fuzzy/non-exact-ID questions
    query_embedding_response = client.models.embed_content(
        model="gemini-embedding-001",
        contents=question,
        config=EmbedContentConfig(task_type="RETRIEVAL_QUERY")
    )
    query_vector = query_embedding_response.embeddings[0].values

    results = collection.query(
        query_embeddings=[query_vector],
        n_results=n_results
    )

    matched_docs = results["documents"][0]
    matched_metadata = results["metadatas"][0]

    if not matched_docs:
        return {"answer": "No relevant vulnerabilities found.", "sources": []}

    context_lines = []
    for doc, meta in zip(matched_docs, matched_metadata):
        context_lines.append(
            f"- {meta['cve_id']} ({meta['severity']}, CVSS {meta['cvss_score']}): {doc}"
        )
    context = "\n".join(context_lines)

    prompt = f"""You are a vulnerability management assistant. Answer the user's question
using ONLY the vulnerability data provided below.

Vulnerability data:
{context}

Question: {question}

Answer:"""

    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt
    )

    return {
        "answer": response.text,
        "sources": [meta["cve_id"] for meta in matched_metadata]
    }