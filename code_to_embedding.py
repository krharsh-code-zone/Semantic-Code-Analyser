import torch
from unixcoder import UniXcoder
import numpy as np

uni = UniXcoder('microsoft/unixcoder-base-nine')

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
uni.to(device)

def code_to_token(codes):
    '''
    Convert string to token ids
    '''
    uni_token = uni.tokenize(codes, mode = "<encoder-only>", max_length=512, padding = True)
    return uni_token


def token_to_embedding(tokens_ids):
    '''
    convert token_ids to tenson to torch(transformer's output)
    tokens_embeddings   [5, 512, 768]    (batchsize, token_length, hidden_layers)
    code_embedding      [5, 768]           (batchsize, hidden_layers)
    '''
    source_ids = torch.tensor(tokens_ids).to(device)
    # print(source_ids)
    tokens_embeddings, code_embedding = uni(source_ids)
    return tokens_embeddings, code_embedding

def torch_to_normal_ndarray(code_embedding):
    '''
    converts torch to normalized array of dim (batch_size, 768)
    '''
    # 2D torch to 1D array
    embeddings = code_embedding.detach().cpu().numpy()
    # normalizing
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    embeddings = embeddings / norms
    return embeddings

def final_embedding_array(codes):
    '''
    codes: list of string of code
    return normalized array of dimension (batch_size, embedding_dim(fixed))
    '''
    token_ids = code_to_token(codes) # 5 512
    _, code_embedding = token_to_embedding(token_ids)
    normal_array = torch_to_normal_ndarray(code_embedding)
    return normal_array

