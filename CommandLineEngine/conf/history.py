"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
class history:
    def __init__(self):
        self.prevset = ''

    def compare(self, text, kworker=False, filter=None):
        self.curset = set(text.splitlines())
        if self.prevset == '':
            diff = self.curset
        else:
            diff = self.curset.difference(self.prevset)
        self.prevset = self.curset

        if filter is not None:
            return [x for x in diff if filter in x]
        elif kworker == False:
             return [x for x in diff if "kworker" not in x and "[ps]" not in x]
        else:
            return [x for x in diff if "[ps]" not in x]

    def write_to_file(self, file_name):
        with open(file_name, 'w') as f:
            f.writelines(self.prevset)

    def read_from_file(self, file_name):
        with open(file_name, 'r') as f:
            self.prevset = set(f.read().splitlines())
