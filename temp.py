# embedding nn
from code_to_embedding import final_embedding_array
#retrieves from chromadb
from query import querring
# tree & data
from datasets import load_dataset
ds = load_dataset("ayshajavd/code-security-vulnerability-dataset")

import tree_sitter_c
LANGUAGE_MAP = {
    'C': tree_sitter_c.language(),
}
def code_chunking_test(thisdict,header,header_len,limit,current_code):
    '''
    takes final dictionary, header, header_len,limit(token limit), current_code
    '''
    chunks = []
    chunk_locations = []
    for depth,inner_dict in thisdict.items():
        for i in range(0,len(inner_dict['eb'])):
            if (inner_dict['eb'][i] - inner_dict['sb'][i]) <= (limit - header_len):
                i_header = [x.rstrip("\n {") for x in header if x is not None]
                f_header = ' > '.join(i_header)
                chunk = f'// Context: {f_header}' + '// code: ' + current_code[inner_dict['sb'][i]:inner_dict['eb'][i]]
                chunk_locations.append((inner_dict['sb'][i], inner_dict['eb'][i]))
                chunks.append(chunk)

    return chunks,chunk_locations

def analyze_chunk_vulnerabilities(results, chunk_locations):
    '''
    Takes the ChromaDB results and the chunk_locations.
    Returns a detailed list mapping each chunk's start/end bytes to its similarity and score.
    '''
    detailed_reports = []

    # zip() lets us iterate through the DB results and the locations simultaneously
    for query_result, location in zip(results, chunk_locations):
        score = 0
        total = 0
        start_byte = location[0]
        end_byte = location[1]

        # Get the distance of the absolute closest match in the DB
        # If query_result is empty, default to 1.0 (lowest similarity)
        top_distance = query_result[0]["distance"] if query_result else 1.0 
        
        # Calculate Cosine Similarity
        cosine_similarity = 1 - top_distance

        # Calculate your weighted vulnerability probability
        for item in query_result[:5]:
            label = item["metadata"]["label"]
            dist = item["distance"]

            w = 1 / (dist + 1e-6)
            total += w
            if label != "safe":
                score += w

        # Final weighted probability (0.0 means 100% safe, 1.0 means highly likely vulnerable)
        vulnerability_prob = score / total if total > 0 else 0
        
        # Determine status based on a threshold (e.g., if prob > 0.5, flag as vulnerable)
        status = "Vulnerable" if vulnerability_prob > 0.5 else "Safe"

        # Append all the specific chunk data to our report
        detailed_reports.append({
            "start_byte": start_byte,
            "end_byte": end_byte,
            "weighted_vuln_score": vulnerability_prob,
            "top_cosine_similarity": cosine_similarity,
            "status": status
        })

    return detailed_reports

from learning_AST import get_parsed_tree,chunking,dict_preprocessing

test_c = ds["test"].filter(lambda x : x["language"] == "C")

def test(i):
    #parse tree bloack
    tree_c = get_parsed_tree(test_c['code'][i],test_c['language'][i])
    root = tree_c.root_node

    #chunking block
    header_test = []
    thisdict_test = {}
    token_limit = 1000 - (2 * len('CWE-798 (Hardcoded Credentials)'))
    lvl = 0
    chunking(root,lvl,token_limit,thisdict_test,test_c['code'][i])

    #thisdict preprocessing
    header_len = 0
    header_len += sum(len(x) for x in header_test if x is not None)
    dict_preprocessing(thisdict_test,token_limit,header_len)

    #code chunking (intermediate)
    chunks, chunk_locations = code_chunking_test(thisdict_test, header_test, header_len, token_limit, test_c['code'][i])

    #embedding
    normal_arrays = final_embedding_array(chunks)

    #retrieveing in chromadb
    all_result = querring(normal_arrays)
    # print(all_result)
    # print('query')

    # prediction
    print('1 ---> Vulnerable, 0 ---> safe')
    print('prediction: ',analyze_chunk_vulnerabilities(all_result,chunk_locations))

test(77)