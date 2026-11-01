#!/usr/bin/env python3
"""AEE × LOGODECRYPT PRIME 1.0 — Nathaniel Michael Jaffe-Norris.
Local deterministic inspection + bounded exploratory transformation.
Python 3.10+ standard library. No network calls, model/API cost, or auto-action.
New consolidation; exact conformance to every historical version is not asserted.
Rule hits are not proof of deception, intent, authorship, truth or culpability.
SHA-256 receipts are integrity records, NOT signatures or independent attestation.
No original corpus/evidence specimens are embedded. All demo inputs are synthetic.
Usage: python aee_logodecrypt_prime.py --demo
       python aee_logodecrypt_prime.py --file input.txt --context source.txt
       python aee_logodecrypt_prime.py --text 'The logs were retained.' --frame privacy
       python aee_logodecrypt_prime.py --self-test
"""
import argparse, collections, hashlib, json, math, pathlib, re, sys, unicodedata
VERSION = "1.0.0"
STRUCT = ['equals', 'plus', 'minus', 'times', 'divided', 'sum', 'total', 'result', 'therefore', 'verified', 'measured', 'computed', 'block', 'hash', 'signature', 'audit', 'error', 'fixed', 'record', 'line', 'index', 'formula', 'matrix', 'vector', 'proof', 'theorem', 'derive', 'derivation', 'node', 'transaction', 'ledger', 'math', 'protocol', 'code', 'public', 'matches', 'first', 'second', 'third', 'finally', 'however', 'specifically', 'namely', 'for example', 'for instance', 'in conclusion', 'in summary', 'in other words', 'that is']
EVAS = ['potentially', 'possibly', 'reportedly', 'apparently', 'arguably', 'essentially', 'basically', 'actually', 'literally', 'really', 'somewhat', 'sort of', 'kind of', 'maybe', 'perhaps', 'allegedly', 'more or less', 'roughly speaking', 'to some extent', 'to some degree', 'it is important to note', 'it is worth noting', 'could be argued', 'going forward', 'moving forward', 'holistic', 'synergies', 'leverage', 'meaningful', 'diverse', 'various', 'faceted', 'evolving', 'landscape', 'exploring', 'committed', 'stakeholders', 'engagement', 'fosters', 'remains', 'suggests', 'implies', 'generally', 'typically', 'likely', 'still under development', 'i apologize for', 'i understand your frustration', 'i appreciate your patience', 'as an ai', "i'm afraid", 'please note that', 'at this time', 'to the best of my knowledge', 'i want to be transparent', 'keep in mind', 'as of my last update', "it's important to note"]

# Associations are stipulated creative anchors, not etymology, WordNet or measured charges.
ANCHORS = dict(zip('abcdefghijklmnopqrstuvwxyz',[
'alpha apex ascent','being body boundary','capture contain curve','delta door dimension',
'energy existence element','force fire flow','generation geometry growth','hinge heart horizon',
'identity illumination instance','join judge journey','kinetic key kernel','line light law',
'matrix matter measure','no negation nucleus','origin orbit one','power point potential',
'question quest quell','rhythm relation resonance','spirit sound silence','tree time structure',
'under unity utter','vessel valley vibration','wave witness weave','nexus crossroads exchange',
'why choice pathway','zenith finality lightning']))
# Symmetric curated lexical poles; sentence-level logical negation is NOT asserted.
PAIRS=[('approved','denied'),('accepted','rejected'),('passed','failed'),('opened','closed'),
       ('increased','decreased'),('above','below'),('public','private'),('retain','delete')]
POLES={a:b for a,b in PAIRS for a,b in [(a,b),(b,a)]}
FRAMES={
 'privacy': {'retention duration':r'\b\d+\s+(?:hours?|days?|weeks?|months?|years?)\b|\buntil\b',
   'deletion mechanism':r'\b(?:delet\w*|eras\w*|remov\w*)\b',
   'human review':r'\b(?:reviewer|manual review|human review|staff review)\b',
   'recipients':r'\b(?:third[- ]part\w*|recipient\w*|share\w* with)\b',
   'opt-out':r'\bopt[- ]?out\b', 'training use':r'\btrain\w*\b',
   'contact channel':r'\b(?:contact|complaint|appeal|email)\b'},
 'license': {'duration':r'\b(?:duration|perpetual|years?|months?|until)\b',
   'revocation':r'\brevoc\w*|\brevoke\w*', 'sublicensing':r'\bsublicen\w*',
   'remedy':r'\b(?:refund\w*|remed\w*|damages)\b', 'governing law':r'governing law|jurisdiction',
   'termination':r'\bterminat\w*', 'liability':r'\bliabilit\w*'},
 'general': {'named first party':r'\b(?:I|we|our)\b','timeline':r'\b\d{4}\b|\b(?:until|within|deadline)\b',
   'verification':r'\b(?:test\w*|verif\w*|audit\w*|receipt\w*)\b',
   'recourse':r'\b(?:appeal|refund|remedy|complaint|contact)\b'}}
STAGES=['capture','lexical-battery','script-sensor','surface-census','frame-ledger',
        'context-fidelity','exploratory-transforms','receipt']
LIMITS=['Patterns are fallible and excerpt-scoped; no fact-check or mind-reading is performed.',
 'A missing keyword does not prove that a clause or capability is absent.',
 'Generated associations and counterfactuals are illustrations, never recovered verbatim omissions.',
 'Modal verbs, passives, punctuation and polite phrases can be legitimate.',
 'Speaker identity, legal conclusions, device state and market demand are not inferred.',
 'The letter layer uses stipulated anchors; historical WordNet/cache charges are not reproduced.']

def canonical(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def sha(x): return hashlib.sha256(x.encode('utf-8')).hexdigest()
def fold(x): return x.translate(str.maketrans({'’':"'",'‘':"'",'“':'"','”':'"'}))
def normalize(x): return ' '+re.sub(r'\s+',' ',re.sub(r"[^a-z0-9:' ]",' ',fold(x).lower())).strip()+' '
def sites(text,pattern,flags=re.I):
    return [{'start':m.start(),'end':m.end(),'quote':m.group(0)} for m in re.finditer(pattern,text,flags)]
def word_tokens(text): return list(re.finditer(r"[A-Za-z]+(?:'[A-Za-z]+)?",text))
def battery(text):
    n=normalize(text)
    def count(t): return len(re.findall(re.escape(t) if ' ' in t else r'\b'+re.escape(t)+r'\b',n))
    sh={t:count(t) for t in STRUCT}; dh={t:count(t) for t in EVAS}
    S,D=sum(sh.values()),sum(dh.values()); letters=re.findall('[A-Za-z]',text);sc=sum(c.lower()=='s' for c in letters)
    l7=math.log(max(S,1),7);l10=math.log10(max(D,1));td=l7/l10 if l10>0 else l7
    pic=(len(letters)+2.64*sc)/len(letters) if letters else 0
    return {'S':S,'D':D,'PIC':round(pic,4),'T_d':round(td,4),'latin_letters':len(letters),
      'words_normalized':len(n.split()),'structural_hits':{k:v for k,v in sh.items() if v},
      'evasion_lexicon_hits':{k:v for k,v in dh.items() if v},
      'historical_battery_condition':('EMPTY' if not text.strip() else 'ZERO-LEXICON-HIT' if S==D==0 else
       'OBJECTIVE' if td>=1 and pic<=1.25 else 'CALCIFYING' if td>=1 else 'SUB-GATE'),
      'interpretation':'Historical condition names are formula labels, not judgments of accuracy or intent.'}
def script_of(c):
    o=ord(c)
    for name,a,b in [('LATIN',0x41,0x24f),('GREEK',0x370,0x3ff),('CYRILLIC',0x400,0x4ff),
      ('HEBREW',0x590,0x5ff),('ARABIC',0x600,0x6ff),('DEVANAGARI',0x900,0x97f),
      ('HIRAGANA',0x3040,0x309f),('KATAKANA',0x30a0,0x30ff),('HAN',0x4e00,0x9fff),('HANGUL',0xac00,0xd7af)]:
        if a<=o<=b:return name
    return 'OTHER'
def scripts(text):
    seq=[script_of(c) for c in text if c.isalpha()]; count=dict(collections.Counter(seq));fusions=[]
    for m in re.finditer(r'\S+',text):
        types=sorted({script_of(c) for c in m.group() if c.isalpha()})
        if len(types)>1:fusions.append({'start':m.start(),'end':m.end(),'quote':m.group(),'scripts':types})
    controls=[{'index':i,'codepoint':f'U+{ord(c):04X}','name':unicodedata.name(c,'UNNAMED')}
              for i,c in enumerate(text) if unicodedata.category(c)=='Cf']
    return {'letters_by_script':count,'transitions':sum(a!=b for a,b in zip(seq,seq[1:])),
      'fusion_tokens':fusions,'format_controls':controls,'nonlatin_share':round(1-count.get('LATIN',0)/len(seq),4) if seq else 0,
      'note':'Range-based TR-7 compatibility census; multilingual text and controls are not intrinsically malicious.'}
def surface(text):
    return {'passive_candidates':sites(text,r'\b(?:am|is|are|was|were|be|been|being|gets?|got)\s+(?:not\s+)?(?:\w+ed|\w+en|kept|made|done|shown|sent|held|said|read|set|put)\b'),
      'indefinite_role_candidates':sites(text,r'\b(?:a|an)\s+(?:reviewer|user|person|individual|employee|contractor|provider|administrator|operator|attacker|reader|manager|agent)\b'),
      'modal_cues':sites(text,r'\b(?:may|might|could|can|must|shall|should)\b'),
      'negation_cues':sites(text,r"\b(?:not|never|without|neither|nor)\b|\b\w+n't\b"),
      'first_party_flow_cues':sites(text,r'\bwe\s+(?:collect|use|share|retain|keep|store|review|process|sell|disclose)\b'),
      'purpose_candidates':sites(text,r'\bto\s+(?:improve|protect|provide|personalize|deliver|support|serve)\b[^.;!?\n]*'),
      'reader_obligation_cues':sites(text,r'\byou\s+(?:must|should|agree|are responsible|will be|understand)\b'),
      'speaker_self_description':sites(text,r'\b(?:as an AI|I am a language model|my training|my guidelines|my policies)\b'),
      'punctuation':{'exclamations':text.count('!'),'questions':text.count('?'),'ellipses':len(re.findall(r'\.\.\.|…',text))}}
def frame_ledger(text,frame):
    return [{'field':k,'status':'MATCHED-CUE' if sites(text,v) else 'NO-CUE-MATCH-IN-EXCERPT',
             'evidence':sites(text,v)} for k,v in FRAMES[frame].items()]
def numbers(text):
    return [m.group().replace(',','').strip().rstrip('.') for m in re.finditer(r'\$?\d[\d,]*(?:\.\d+)?(?:\s*%)?',text)]
def fidelity(context,candidate):
    if context is None:return {'status':'NOT-RUN','reason':'No independent/source context supplied.'}
    a,b=collections.Counter(numbers(context)),collections.Counter(numbers(candidate))
    swaps=[]
    for x,y in PAIRS:
        for old,new in [(x,y),(y,x)]:
            if re.search(r'\b'+old+r'\b',context,re.I) and not re.search(r'\b'+old+r'\b',candidate,re.I) and re.search(r'\b'+new+r'\b',candidate,re.I):
                swaps.append({'source_pole':old,'candidate_pole':new})
    new=list((b-a).elements());missing=list((a-b).elements())
    return {'status':'REVIEW-CUES' if new or missing or swaps else 'NO-SELECTED-CUE-DIFFERENCE',
       'source_sha256':sha(context),'candidate_numbers_not_in_source_multiset':new,
       'source_numbers_not_in_candidate_multiset':missing,'curated_polarity_changes':swaps,
       'limits':'No semantic entailment/role binding: reordered numbers in different roles may escape this check; word changes may be legitimate.'}
def transforms(text,cap=12):
    tokens=word_tokens(text);selected=tokens[:cap];rows=[]
    for m in selected:
        t=m.group();per=[{'letter':c,'anchors':ANCHORS[c]} for c in t.lower() if c in ANCHORS]
        rows.append({'token':t,'start':m.start(),'end':m.end(),'letters':per,
          'association_acrostic':' '.join(ANCHORS[c].split()[0] for c in t.lower() if c in ANCHORS)})
    gaps=[{'left':a.group(),'right':b.group(),'separator_verbatim':text[a.end():b.start()]}
          for a,b in zip(tokens,tokens[1:])]
    inverse=re.sub(r'\b(?:'+ '|'.join(map(re.escape,POLES))+r')\b',lambda m:POLES[m.group().lower()],text,flags=re.I)
    neg=sites(text,r'\bnot\s+(?:\w+\s+){0,5}\w+',re.I)
    return {'source_verbatim':text,
       'literal_projection':'\n'.join(f'{k}: '+('; '.join(h['quote'] for h in v) or 'NONE MATCHED')
          for k,v in surface(text).items() if isinstance(v,list)),
       'generated_association':{'label':'GENERATED ASSOCIATION — stipulated letter keys, NOT decoded meaning',
         'max_tokens':cap,'tokens_processed':len(selected),'tokens_omitted':max(0,len(tokens)-cap),'token_records':rows},
       'counterfactual_lexical_flip':{'label':'GENERATED COUNTERFACTUAL — curated word substitution, NOT recovered intent or logical negation',
          'text':inverse,'changed':inverse!=text},
       'negated_payloads':{'label':'QUOTED NEGATION WINDOWS — preserve not; removing it would alter the source text','spans':neg},
       'silence_rows':gaps,'inverted_letter_index':{c:sorted({r['token'] for r in rows if c in r['token'].lower()}) for c in sorted({c for r in rows for c in r['token'].lower() if c in ANCHORS})}}
def analyze(text,context=None,frame='general',token_cap=12):
    if not 1<=token_cap<=100:raise ValueError('token_cap must be 1..100')
    result={'tool':'AEE × LOGODECRYPT PRIME','version':VERSION,'source_verbatim':text,
       'evidence_class':'calculated text-pattern observables plus explicitly generated illustrations',
       'battery':battery(text),'scripts':scripts(text),'surface':surface(text),
       'frame':frame,'frame_ledger':frame_ledger(text,frame),'context_fidelity':fidelity(context,text),
       'transformations':transforms(text,token_cap),'limitations':LIMITS}
    result['receipt']={'input_sha256':sha(text),'context_sha256':sha(context) if context is not None else None,
       'output_sha256_excluding_receipt':sha(canonical(result)), 'stages_executed':STAGES,
       'receipt_type':'UNSIGNED SHA256 INTEGRITY RECORD','tool_version':VERSION}
    return result
def verify(result):
    d=dict(result);r=d.pop('receipt');return r['input_sha256']==sha(d['source_verbatim']) and r['output_sha256_excluding_receipt']==sha(canonical(d))
DEMOS=[
 {'id':'permission-is-not-proof','frame':'privacy','text':'We may retain diagnostic logs to improve reliability. A reviewer may inspect submitted incidents. We do not use the logs to train the public model.','context':None},
 {'id':'confidence-is-not-fidelity','frame':'general','text':'The test passed for 15 records.','context':'The test failed for 12 records.'},
 {'id':'missing-is-not-recovered','frame':'privacy','text':'Logs are retained. Contact support to request deletion.','context':None},
 {'id':'invisible-boundary','frame':'general','text':'The pаyload contains admin\u200bistrator.','context':None},
 {'id':'letters-are-not-intent','frame':'general','text':'Trust is earned, not announced.','context':None},
 {'id':'polite-and-accurate-control','frame':'general','text':'Perhaps the test failed; the source says it failed.','context':'The test failed.'}]
def demo():return [{'id':d['id'],'result':analyze(d['text'],d['context'],d['frame'])} for d in DEMOS]
def self_test():
    checks=[]
    def check(name,condition):
        if not condition:raise AssertionError(name)
        checks.append(name)
    for t in ['', '123 !!!','verified code perhaps','pаyload','May 12, 2026','not public.','שלום العربية']:
        a=analyze(t);check('receipt '+repr(t),verify(a));check('determinism '+repr(t),a==analyze(t));check('preservation '+repr(t),a['source_verbatim']==t)
    check('lexical S',battery('verified code')['S']==2)
    check('lexical D',battery('perhaps perhaps')['D']==2)
    check('no substrings',battery('codes unverifi ed')['S']==0)
    check('phrase matching',battery('for example')['S']==1)
    check('script fusion',len(scripts('pаyload')['fusion_tokens'])==1)
    check('format control',len(scripts('admin\u200bistrator')['format_controls'])==1)
    check('number change',fidelity('12 records','15 records')['candidate_numbers_not_in_source_multiset']==['15'])
    check('number reorder',not fidelity('12 and 15','15 and 12')['candidate_numbers_not_in_source_multiset'])
    check('polarity',bool(fidelity('test failed','test passed')['curated_polarity_changes']))
    check('involution on curated lower-case tokens',transforms(transforms('public approved')['counterfactual_lexical_flip']['text'])['counterfactual_lexical_flip']['text']=='public approved')
    check('bounded expansion',transforms('one two three',2)['generated_association']['tokens_omitted']==1)
    for h in surface('A reviewer may inspect. Logs were retained.')['passive_candidates']:
        check('source offsets','A reviewer may inspect. Logs were retained.'[h['start']:h['end']]==h['quote'])
    a=analyze('record');a['source_verbatim']='changed';check('tamper detection',not verify(a))
    check('not synonym decoding','NOT decoded meaning' in transforms('trust')['generated_association']['label'])
    check('negation preserved','not public' in transforms('not public')['negated_payloads']['spans'][0]['quote'])
    return {'passed':len(checks),'failed':0,'checks':checks,'scope':'unit/smoke tests, NOT independent semantic validity or performance benchmark'}
def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    g=p.add_mutually_exclusive_group();g.add_argument('--text');g.add_argument('--file');g.add_argument('--demo',action='store_true');g.add_argument('--self-test',action='store_true')
    p.add_argument('--context',help='UTF-8 independent/source context file');p.add_argument('--frame',choices=FRAMES,default='general');p.add_argument('--token-cap',type=int,default=12)
    p.add_argument('--output',help='Write JSON output to a NEW file (never overwrite)')
    a=p.parse_args();context=pathlib.Path(a.context).read_text(encoding='utf-8') if a.context else None
    obj=self_test() if a.self_test else demo() if a.demo else analyze(pathlib.Path(a.file).read_text(encoding='utf-8') if a.file else a.text if a.text is not None else sys.stdin.read(),context,a.frame,a.token_cap)
    rendered=json.dumps(obj,ensure_ascii=False,indent=2)+'\n'
    if a.output:
        with open(a.output,'x',encoding='utf-8') as f:f.write(rendered)
    else:print(rendered,end='')
if __name__=='__main__':main()
