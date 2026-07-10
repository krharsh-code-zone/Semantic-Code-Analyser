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

def vulnerability_score(results):
    scores = []

    for query_result in results:

        score = 0
        total = 0

        for item in query_result[:5]:
            label = item["metadata"]["label"]
            dist = item["distance"]

            w = 1 / (dist + 1e-6)

            total += w
            if label != "safe":
                score += w

        scores.append(score / total)

    return scores

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
    print('prediction: ',vulnerability_score(all_result))

test(56)