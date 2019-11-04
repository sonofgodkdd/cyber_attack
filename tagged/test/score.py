import os

from bs4 import BeautifulSoup as Soup


class XmlParser():
    def __init__(self):
        self.xml_dom = ''
        self.types = ['DISCOVER.Misconfiguration', 'DISCOVER.Kernel_Flaws',
                    'DISCOVER.Buffer_Overflow', 'DISCOVER.Insufficient_Authentication_Validation',
                    'DISCOVER.SQLI', 'DISCOVER.XSS', 'DISCOVER.Back_door',
                    'DISCOVER.Incorrect_Permission', 'DISCOVER.Social_Engineering',
                    
                    'PATCH.Misconfiguration', 'PATCH.Kernel_Flaws',
                    'PATCH.Buffer_Overflow', 'PATCH.Insufficient_Authentication_Validation',
                    'PATCH.SQLI', 'PATCH.XSS', 'PATCH.Back_door',
                    'PATCH.Incorrect_Permission', 'PATCH.Social_Engineering',
                    
                    'ATTACK.User_Compromise', 'ATTACK.Root_Compromise', 'ATTACK.Web_Compromise',
                    'ATTACK.Viruss', 'ATTACK.Spyware', 'ATTACK.Trojan', 'ATTACK.Worms',
                    'ATTACK.Arbitrary_Code_Execution', 'ATTACK.DoS',
                    
                    'IMPACT.Distort', 'IMPACT.Disrupt', 'IMPACT.Destruct',
                    'IMPACT.Breach', 'IMPACT.Discovery']

    
    def parse(self, xml_path):
        evs = []
        self.xml_dom = Soup(open(xml_path, 'r', encoding='UTF-8'), 'xml')

        for ev_type in self.types:
            events = self.xml_dom.find_all(ev_type)
            for event in events:
                start = int(event['start'])
                end = int(event['end'])
                text = event['text']

                len_text = len(text)
                start += len_text - len(text.lstrip())
                end -= (len_text - len(text.rstrip()))

                evs.append((start, end, ev_type, text.strip()))
        
        return evs

# parse_xml = XmlParser('20120919T1832000200.xml')

# print(parse_xml.parser())

def Precision_recall_1vs1(path_goal, path_test):
    xml_parser = XmlParser()
    events_doc_goal = xml_parser.parse(path_goal)
    events_doc_test = xml_parser.parse(path_test)
    print(events_doc_test)
    print(events_doc_goal)

    tp = 0
    for item in events_doc_test:
        if item in events_doc_goal:
            tp += 1
    precision = (tp + 0.01) / len(events_doc_test) 
    recall = (tp + 0.01) / len(events_doc_goal)
    f_1 = 2 * precision * recall / (precision + recall)
    return f_1, precision, recall, tp, len(events_doc_test), len(events_doc_goal)

# print(Precision_recall_1vs1('.\\thn_data\\cyber_attack\\new_anotate\\20120919T1832000200.xml', '.\\thn_data\\cyber_attack\\new_anotate\\20120919T1832000200.xml'))
                
def Compute_agree_score(path_goal, path_test):

    files = [filename
            for filename in os.listdir(path_goal)
            if os.path.isfile(os.path.join(path_test, filename))]
    
    tp = 0
    test_len = 0
    goad_len = 0

    for item in files:
        doc_test_path = path_test + '\\' + item
        doc_goal_path = path_goal + '\\' + item
        print(doc_test_path)
        print(doc_goal_path)
        doc_f1, doc_precision, doc_recall, doc_tp, doc_test_len, doc_goad_len = Precision_recall_1vs1(doc_goal_path, doc_test_path)
        tp += doc_tp
        test_len += doc_test_len
        goad_len += doc_goad_len
    
    precision = tp / test_len
    recall = tp / goad_len
    f_1 = 2 * precision * recall / (precision + recall)

    return f_1, precision, recall

f1, precision, recall = Compute_agree_score('.\\thn_data\\cyber_attack\\new_anotate', '.\\thn_data\\cyber_attack\\DucLt')

print('F1 all: ')
print(f1)

print('Precision all: ')
print(precision)

print('Recall all: ')
print(recall)

