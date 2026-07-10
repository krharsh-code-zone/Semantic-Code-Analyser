import chromadb

def storing_chromadb(k,normal_array,chunks,chunk_locations,label):
    client = chromadb.PersistentClient(path="./chroma_db")

    collection = client.get_or_create_collection(
        name="code_embeddings"
    )
    for i in range(0,len(chunk_locations)):
        collection.add(
            ids=[f"{k}_{i}"],
            embeddings=[normal_array[i]],
            documents=[chunks[i]],
            metadatas=[
                {
                    "label": label,
                    'start_byte': chunk_locations[i][0],
                    'end_byte': chunk_locations[i][1],
                }
            ]
        )