# Part of your Tree                                 Where it goes?
# primitive_type, identifier, parameter_list        Header: Included in every chunk.
# declaration, expression_statement                 Chunk 1: The starting logic.
# if_statement (Outer Logic), labeled_statement     Chunk 2: The middle logic.
# if_statement (Inner Logic), update_expression     Chunk 3: The deep logic.
# return_statement, }                               Final Chunk: The exit logic.

# embedding nn
from code_to_embedding import final_embedding_array
#save unixcoder_embedding
from save_unixcoder_embedding import save_unix_array
#store in chromadb
from chroma import storing_chromadb
# tree & data
import ast
import pandas as pd
import sys
from pprint import pprint
from datasets import load_dataset

ds = load_dataset("ayshajavd/code-security-vulnerability-dataset")
vuln = ds["train"].filter(lambda x: x["is_vulnerable"])
non_vuln = ds['train'].filter(lambda x: x['code_fixed'])
lang = ds["train"]["language"]
lang_known = ds["train"].filter(lambda x : x["language"] != "unknown")

import tree_sitter
import tree_sitter_c
import tree_sitter_php
import tree_sitter_python
import tree_sitter_cpp
import tree_sitter_fortran
import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_kotlin
import tree_sitter_ruby
import tree_sitter_swift
import tree_sitter_c_sharp
from tree_sitter import Language, Parser
LANGUAGE_MAP = {
    'C': tree_sitter_c.language(),
    'C#': tree_sitter_c_sharp.language(),
    'C++': tree_sitter_cpp.language(),
    'CPP': tree_sitter_cpp.language(),
    'FORTRAN': tree_sitter_fortran.language(),
    'GO': tree_sitter_go.language(),
    'JAVA': tree_sitter_java.language(),
    'JAVASCRIPT': tree_sitter_javascript.language(),
    'KOTLIN': tree_sitter_kotlin.language(),
    'PHP': tree_sitter_php.language_php(),
    'PYTHON': tree_sitter_python.language(),
    'RUBY': tree_sitter_ruby.language(),
    'SWIFT': tree_sitter_swift.language()
}


def get_parsed_tree(code, lang_name):
    # Normalize language name
    lang_key = lang_name.upper()
    if lang_key not in LANGUAGE_MAP:
        return None

    parser = Parser(Language(LANGUAGE_MAP[lang_key]))

    # This 'tree' is the magical Bucket 2 object we need!
    tree = parser.parse(bytes(code, "utf8"))

    # We return the actual tree object instead of the string
    return tree

def cnk(root, needed):
    # goes through every node possible for given root.
    # returns the end_byte on needed node.
    for child in root.children:
        if child.type == needed:
            return child.end_byte
        result = cnk(child, needed)
        if result is not None:
            return result
    return None

def header_c(child,current_code):
    '''
    generates header for the specific level of depth and bloack of code.
    currently only generating header for: func, loop, conditionals(only: if, else, elif) and (future: class name)
    '''
    # for child in root.children:
    node = child.type
    # print(node)
    if node == "function_definition" or node == "function_declarator":
        # print(child.start_byte,cnk(child,"{"))
        return current_code[child.start_byte : cnk(child,"{")]

    elif node == "if_statement" or node == "switch_statement":
        return current_code[child.start_byte : cnk(child, "parenthesized_expression")]
    elif node == "else_clause":
        is_else_if = False
        for sub_child in child.children:
            if sub_child.type == "if_statement":
                is_else_if = True
                break
        # Check if it's an 'else if'
        if is_else_if:
            cond_end = cnk(child, "parenthesized_expression")
            return "else " + current_code[child.children[1].start_byte : cond_end]
        return "else"

    elif node == "for_statement" or node == "while_statement":
        result = current_code[child.start_byte : cnk(child,"update_expression")]
        if result is None:
            result = current_code[child.start_byte : cnk(child,"binary_expression")]
        else:
            result = current_code[child.start_byte : cnk(child,"assignment_expression")]
        if len(result) > 150:
            result = current_code[child.start_byte : cnk(child,"{")]
        return result
    elif node == "do_statement":
        return "do"

    return None

header = []
def chunking(root,lvl,limit,depth,current_code):
    depth[lvl] = {
            "sb": [],
            'eb': [],

        }
    for child in root.children:
        header_len = 0

        depth[lvl]['sb'].append(child.start_byte)
        depth[lvl]['eb'].append(child.end_byte)

        # print(f"level-{lvl} child:  {child.type}  ({child.start_byte} , {child.end_byte})")
        if child.end_byte - child.start_byte > (limit-header_len):

            chunk_header = header[0:lvl]
            header_len += sum(len(x) for x in header[0:lvl] if x is not None)
            # print(header_len, chunk_header)
            # depth[lvl]['header'] = chunk_header
            # for char in
            lvl += 1

            header.append(header_c(child,current_code))

            chunking(child,lvl,limit,depth,current_code)
    # depth['header'] = header

def dict_preprocessing(thisdict,limit,header_len):
    for depth ,inner_dict in thisdict.items():
        # print(inner_dict)
        i = 0
        j = 0
        temp_sb = []
        temp_eb = []

        while j < len(inner_dict['eb']):

            temp_len = inner_dict['eb'][j] - inner_dict['sb'][i]

            if temp_len > (limit - header_len):
                temp_sb.append(inner_dict['sb'][i])
                temp_eb.append(inner_dict['eb'][j-1])
                i = j+1
                j += 1

            elif j == len(inner_dict['eb']) - 1:
                temp_sb.append(inner_dict['sb'][i])
                temp_eb.append(inner_dict['eb'][j])
                break
            j += 1

        inner_dict['sb'] = temp_sb
        inner_dict['eb'] = temp_eb

def code_chunking(thisdict,header,header_len,limit,current_code, current_labels):
    '''
    takes final dictionary, header, header_len,limit(token limit), current_code
    '''
    labels = [
        "safe",                           # 0
        "CWE-20 (Input Validation)",      # 1
        "CWE-22 (Path Traversal)",        # 2
        "CWE-78 (Command Injection)",     # 3
        "CWE-79 (XSS)",                   # 4
        "CWE-89 (SQL Injection)",         # 5
        "CWE-94 (Code Injection)",        # 6
        "CWE-119 (Buffer Overflow)",      # 7
        "CWE-125 (Out-of-bounds Read)",   # 8
        "CWE-190 (Integer Overflow)",     # 9
        "CWE-200 (Information Exposure)", # 10
        "CWE-264 (Permissions)",          # 11
        "CWE-269 (Privilege Management)", # 12
        "CWE-276 (Default Permissions)",  # 13
        "CWE-284 (Access Control)",       # 14
        "CWE-287 (Authentication)",       # 15
        "CWE-310 (Cryptographic Issues)", # 16
        "CWE-327 (Broken Cryptography)",  # 17
        "CWE-330 (Weak Randomness)",      # 18
        "CWE-352 (CSRF)",                 # 19
        "CWE-362 (Race Condition)",       # 20
        "CWE-399 (Resource Management)",  # 21
        "CWE-401 (Memory Leak)",          # 22
        "CWE-416 (Use After Free)",       # 23
        "CWE-434 (File Upload)",          # 24
        "CWE-476 (NULL Dereference)",     # 25
        "CWE-502 (Deserialization)",      # 26
        "CWE-601 (Open Redirect)",        # 27
        "CWE-787 (Out-of-bounds Write)",  # 28
        "CWE-798 (Hardcoded Credentials)",# 29
        "CWE-918 (SSRF)"                  # 30
]
    active_label = [labels[i] for i,v in enumerate(current_labels) if v == 1.0]
    chunks = []
    chunk_locations = []
    for depth,inner_dict in thisdict.items():
        for i in range(0,len(inner_dict['eb'])):
            if (inner_dict['eb'][i] - inner_dict['sb'][i]) <= (limit - header_len):
                i_header = [x.rstrip("\n {") for x in header if x is not None]
                f_header = ' > '.join(i_header)
                chunk = f'// Context: {f_header}' + f'// vuln: {active_label}' + '// code: ' + current_code[inner_dict['sb'][i]:inner_dict['eb'][i]]
                chunk_locations.append((inner_dict['sb'][i], inner_dict['eb'][i]))
                chunks.append(chunk)

    return chunks,chunk_locations,active_label

'''
Data collection/ accessing
DatasetDict({
    train: Dataset({
        features: ['code', 'code_fixed', 'cwe_id', 'owasp', 'language', 'source', 'is_vulnerable', 'labels'],
        num_rows: 140335
    })
    validation: Dataset({
        features: ['code', 'code_fixed', 'cwe_id', 'owasp', 'language', 'source', 'is_vulnerable', 'labels'],
        num_rows: 17542
    })
    test: Dataset({
        features: ['code', 'code_fixed', 'cwe_id', 'owasp', 'language', 'source', 'is_vulnerable', 'labels'],
        num_rows: 17542
    })
})
'''
train_c = ds["train"].filter(lambda x : x["language"] == "C")
validation_c = ds["validation"].filter(lambda x : x["language"] == "C")
test_c = ds["test"].filter(lambda x : x["language"] == "C")

def last():
    for i in range(0,1000):
        #parse tree bloack
        tree_c = get_parsed_tree(train_c['code'][i],test_c['language'][i])
        root = tree_c.root_node

        #chunking block
        header = []
        thisdict = {}
        token_limit = 1000 - (2 * len('CWE-798 (Hardcoded Credentials)'))
        lvl = 0
        chunking(root,lvl,token_limit,thisdict,train_c['code'][i])

        #thisdict preprocessing
        header_len = 0
        header_len += sum(len(x) for x in header if x is not None)
        dict_preprocessing(thisdict,token_limit,header_len)

        #code chunking (intermediate)
        chunks, chunk_locations, active_label = code_chunking(thisdict, header, header_len, token_limit, train_c['code'][i], train_c['labels'][i])
        # print(chunks)
        # print(chunk_locations,i)
        

        #embedding
        normal_arrays = final_embedding_array(chunks)

        # #storing unixcoder-embedding
        # save_unix_array(i,chunks,active_label,normal_arrays,chunk_locations)

        #storing in chromadb
        storing_chromadb(i,normal_arrays,chunks,chunk_locations,active_label)
        print(f"succesfully stored {i}")

# last()