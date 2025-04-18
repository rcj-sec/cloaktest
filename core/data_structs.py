import bisect

from utils import pretty_print as print

class ExclusiveListManager:
    def __init__(self, names: list[str]):
        self._lists: dict[str, list] = {name: [] for name in names}

    def add(self, dst_list_name, item):
        if dst_list_name not in self._lists:
            print.error(f'[!] Cannot add "{item}" to "{dst_list_name}". List name "{dst_list_name}" not registered in ExclusiveListManager.')
            return False

        for name in self._lists:
            if dst_list_name != name and item in self._lists[name]:
                self._lists[name].remove(item)
        
        if item not in self._lists[name]:
            bisect.insort(self._lists[dst_list_name], item)

        return True

    def get(self, list_name):
        if list_name not in self._lists:
            print.error(f'[!] Cannot get "{list_name}". List name "{list_name}" not registered in ExclusiveListManager.')
            return None
        return self._lists[list_name]
    
    def to_dict(self):
        return self._lists

