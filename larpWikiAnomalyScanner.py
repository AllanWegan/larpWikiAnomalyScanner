#!/usr/bin/env python3
#
# Scans all wiki page sources in current directory and outputs found anomalies
# to stdout in a human readable format.
#
# Detected anomalies:
# - Obscure code points:
#   - Replacement code point "�".
#   - Marks in grapheme clusters without a leading letter.
#   - Category C except tab.
# - Invalid wiki directives:
#   - Redirect in other than first line after optional leading comments.
#   - Any non-comment non-directive after valid redirect.
# - Old wiki tags:
#   - <b>
#   - <br>
#   - <i>
#   - <nowiki>
#   - <pre>
#   - <toc>
#   - <tt>
# - Tag case:
#   - <<BR>>
# - Headlines:
#   - leading or trailing whitespace.
#   - Open and close tags of differing length.
#   - Level > 5.
#   - Missing whitespace between tags and headline text.
#   - Headlines with leading "#" or "*" in name (leftovers from old wiki).
#   - Missing headline text (except "#" or "*").
#   - Markup in text.
# - Links:
#   - Quoted internal links (failed old wiki conversion).
#   - Old-wiki-style external links.
#   - Old-wiki-style upload/attachment links.
# - Lists:
#   - Old-wiki-style bullet lists (line starts with '*')
#   - Old-wiki-style numbered list (line starts with '#') when mixed with 
#     bullet lists (else they look like a directive or comment).
# - Old wiki paragraph modes:
#   - Indenting (leading ':').
#   - Definition list (leading ';').
#
# 2012-12-26 Allan Wegan <allanwegan@allanwegan.de>
#

import glob
import os
import platform
import sys
import unicodedata

blacklist = (
  r'HilfeZurCreoleSyntax.txt',
  r'.')

# Finds all occurences of a regular expression pattern in given :
import re
class ReCache:
  
  cache = dict()
  
  def compile(self, pattern, flags = 0):
    cache = self.cache
    if pattern not in cache:
      cache[pattern] = dict()
    cache = cache[pattern]
    if flags not in cache:
      cache[flags] = re.compile(pattern, flags)
    return cache[flags]
  def finditer(self, pattern, text, flags = 0):
    return self.compile(pattern, flags).finditer(text)
  def match(self, pattern, text, flags = 0):
    return self.compile(pattern, flags).match(text)
  def search(self, pattern, text, flags = 0):
    return self.compile(pattern, flags).search(text)
  def sub(self, pattern, replacement, text, flags = 0):
    return self.compile(pattern, flags).sub(replacement, text)

# Outputs found anomalies:
import urllib.parse
class AnomalyOutputter:
   
  o = None
  e = None
  d = None
  qoute = r'"'
  ellipsis = r'…'
  sol = r'|'
  eol = r'|'
  maxPartLength = 70
  minAfterLength = 20
  
  pathCount = 0
  lineCount = 0
  anomalyCount = 0
  anomalyCounts = dict()
  lastPath = r''
  lastLineNr = 0
  
  def __init__(self, outputStream, textEscaper, textDecorator):
    self.o = outputStream
    self.e = textEscaper
    self.d = textDecorator
  
  def out(self, path, lineNr, startColumn, endColumn, line, anomaly):
    o = self.o
    e = self.e
    d = self.d
    q = self.qoute
    if self.lastPath != path:
      self.lastPath = path
      self.pathCount += 1
      ePath = d.decorateText(e.escape(path), d.textBCyan)
      pageName = path.replace(r' - ', r'/')
      if pageName[-4:] == r'.txt':
        pageName = pageName[0:-4]
      url = r'https://larpwiki.de/' + urllib.parse.quote(pageName)
      eUrl = d.decorateText(url, d.textWhite)
      o.write('\n%s%s%s\n<%s>:\n' % (q, ePath, q, eUrl))
    if self.lastLineNr != lineNr:
      if self.lastLineNr != lineNr:
        self.lineCount += 1
        self.lastLineNr = lineNr
      eLineNr = d.decorateText(str(lineNr + 1), d.textBYellow)
      o.write('  Line %s:\n' % (eLineNr))
    self.anomalyCount += 1
    if anomaly not in self.anomalyCounts:
      self.anomalyCounts[anomaly] = 1
    else:
      self.anomalyCounts[anomaly] += 1
    eColumn = d.decorateText(str(startColumn + 1), d.textBYellow)
    
    ml = self.maxPartLength
    # Extract as much of the anomaly as allowed and selected:
    t = e.escapeLimitRight(line[startColumn:endColumn], ml)
    part = t[0]
    partCpLength = t[1]
    partComplete = ((endColumn - startColumn - partCpLength) == 0)
    ml = max(0, ml - len(part))
    # Extract leading text but reserve some quota for trailing:
    if partComplete:
      mal = min(len(line) - endColumn, ml, int(ml / 2), self.minAfterLength)
    else:
      mal = 0
    bLength = min(startColumn, ml - mal)
    t = e.escapeLimitLeft(line[:startColumn], bLength)
    before = t[0]
    beforeCpLength = t[1]
    ml = max(0, ml - len(before))
    # Extract as much of trailing text as available and quota left:
    if partComplete:
      t = e.escapeLimitRight(line[endColumn:], ml)
      after = t[0]
      afterCpLength = t[1]
    else:
      after = r''
      afterCpLength = 0
    
    if startColumn - beforeCpLength > 0:
      sol = self.ellipsis
    else:
      sol = self.sol
    if (startColumn + partCpLength + afterCpLength) < len(line):
      eol = self.ellipsis
    else:
      eol = self.eol
    before = d.decorateText(before, d.textYellow)
    part = d.decorateText(part, d.textBYellow, d.textUnderline)
    after = d.decorateText(after, d.textYellow)
    o.write('    Column %s, anomaly %s%s%s:\n' % (eColumn, q, anomaly, q))
    o.write('      %s%s%s%s%s%s%s\n' % (sol, q, before, part, after, q, eol))

# Colorizes output for ANSI terminals:
class AnsiTextDecorator:
  
  textBlack = r'30'
  textRed = r'31'
  textGreen = r'32'
  textYellow = r'33'
  textBlue = r'34'
  textMagenta = r'35'
  textCyan = r'36'
  textGrey = r'37'
  textBGrey = r'30;1'
  textBRed = r'31;1'
  textBGreen = r'32;1'
  textBYellow = r'33;1'
  textBBlue = r'34;1'
  textBMagenta = r'35;1'
  textBCyan = r'36;1'
  textWhite = r'37;1'
  textBold = r'1'
  textItalic = r'3'
  textUnderline = r'4'
  backgroundBlack = r'40'
  backgroundRed = r'41'
  backgroundGreen = r'42'
  backgroundYellow = r'43'
  backgroundBlue = r'44'
  backgroundMagenta = r'45'
  backgroundCyan = r'46'
  backgroundGrey = r'47'
  
  def decorateText(self, text, *codes):
    if not len(codes):
      return text
    codesString = r''
    for code in codes:
      codesString += '\x1B[' + code + r'm'
    return codesString + text + '\x1B[0m'

class dummyTextDecorator(AnsiTextDecorator):
  def decorateText(self, text, *codes):
    return text

# Escapes non-printable code points except space (0x20) in given text:
from io import StringIO
class TextEscaper:
  
  def escape(self, text):
    if not len(text): return r''
    return repr(text)[1:-1].replace(r'"', r'\"')

  def escapeLimitRight(self, text, maxLength):
    if maxLength <= 0: return (r'', 0)
    buffer = StringIO()
    length = 0
    cpCount = 0
    for cp in text:
      cp = self.escape(cp)
      newLength = length + len(cp)
      if newLength > maxLength:
        break
      buffer.write(cp)
      cpCount += 1
      length = newLength
      if length == maxLength:
        break
    return (buffer.getvalue(), cpCount)
  
  def escapeLimitLeft(self, text, maxLength):
    if maxLength <= 0: return (r'', 0)
    cpList = []
    length = 0
    index = len(text)
    while index > 0:
      index -= 1
      cp = self.escape(text[index])
      newLength = length + len(cp)
      if newLength > maxLength:
        break
      cpList.append(cp)
      length = newLength
      if length == maxLength:
        break
    cpList.reverse()
    buffer = StringIO()
    for cp in cpList:
      buffer.write(cp)
    return (buffer.getvalue(), len(cpList))

o = sys.stdout
e = TextEscaper()
if o.isatty() and (platform.system() != r'Windows'):
  d = AnsiTextDecorator()
  import subprocess
  cols = int(subprocess.Popen(('tput', 'cols'), 
    stdout=subprocess.PIPE).stdout.read())
  if cols <= 0:
    cols = 80
else:
  d = dummyTextDecorator()
  cols = 80
ao = AnomalyOutputter(o, e, d)
ao.maxPartLength = cols - 11
rec = ReCache()

# Test all *.txt files:
o.write('Scanning files...\n')
fileCount = 0
blistedCount = 0
paths = glob.iglob(r"*.txt")
for path in paths:
  if not os.path.isfile(path):
    continue
  if path in blacklist:
    blistedCount += 1
    continue
  fileCount += 1
  file = open(path, 'r')
  lineNr = -1
  firstDirectiveLine = 1
  validRedirectPresent = False
  for line in file:
    line = rec.sub("\n$", r'', line)
    lineNr += 1
    commentLine = (rec.match(r'##+\s', line) != None)
    directiveLine = not commentLine and (rec.match(r'#[^#]', line) != None)
    
    # Obscure code points:
    markAllowed = False
    lineLength = len(line)
    for lineIndex, cp in enumerate(line):
      anomaly = False
      unexpectedMark = False
      cpCat = unicodedata.category(cp)
      cpCatMain = cpCat[0]
      
      if cpCatMain == r'L':
        markAllowed = True
        continue
      
      if cpCatMain != r'M':
        markAllowed = False
      
      if cp == r'�': # REPLACEMENT CHARACTER, category So
        anomaly = True
      
      if not anomaly:
        if cpCatMain in (r'N', r'P', r'S', r'Z') or cp in (
          '\t', 
          '\xad', # SOFT HYPHEN, category Cf
          '\u200d', # ZERO WIDTH JOINER, category Cf
          '\u200e', # LEFT-TO-RIGHT MARK, category Cf
          None):
          continue
        if cpCatMain in (r'M'): # Special handling for marks.
          if markAllowed:
            continue
          # Not in letter cluster.
          anomaly = True
          unexpectedMark = True
      
      # @Todo: There are legitimate code points for RTL-languages in Cf.
      
      # Handle anomaly:
      before = line[max(0, lineIndex - 30):lineIndex]
      after = line[lineIndex + 1:lineIndex + 31]
      cpName = unicodedata.name(cp, r'unnamed')
      if unexpectedMark:
        suffix = r' not preceded by a letter'
      else:
        suffix = r''
      ao.out(path, lineNr, lineIndex, lineIndex + 1, line,
        (r'Unicode %s (%s, category %s)' + suffix)
        % (e.escape(cp), cpName, cpCat))
    
    # Old-wiki-style lists:
    match = rec.match(r'(\*|#(\*|#(\*|#)))[*#]*', line)
    if match:
      directiveLine = False
      commentLine = False
      start = match.start()
      end = match.end()
      ao.out(path, lineNr, start, end, line, r'Old wiki list')

    # No further wiki syntax checks for comments or after valid redirects:
    if commentLine:
      continue
    
    # Determine first directive line
    if (firstDirectiveLine == lineNr) and commentLine:
      firstDirectiveLine += 1

    # Detect extra non-comment markup after valid redirect:
    if validRedirectPresent and not directiveLine:
      match = rec.match(r'\s*(\S.*?)\s*$', line)
      if match:
        start = match.start(1)
        end = match.end(1)
        ao.out(path, lineNr, start, end, line,
          r'Non-empty non-comment line after valid redirect')
        continue

    # Detect redirects:
    match = rec.match(r'#REDIRECT(\s*)(?P<name>.*)', line)
    if match:
      if firstDirectiveLine:
        name = match.group(r'name')
        if not name:
          ao.out(path, lineNr, 0, len(line), line, r'Redirect without target')
        else:
          validRedirectPresent = True
      else:
        ao.out(path, lineNr, 0, len(line), line, r'Redirect in non-first line')
      continue

    # Skip other directives:
    if directiveLine:
      continue

    # Old-wiki-style features dependent on first char of line:
    match = rec.match(r'''^(?P<firstChar>[:;])((?P<extraChars>[:;]*)|($|
      [^-\(\{\[\|\)\}\]pPD] # Do not match smilies.
      ))''', line, re.VERBOSE)
    if match:
      linePartPos = match.start()
      linePart = match.group()
      firstChar = match.group(r'firstChar')
      extraCount = len(match.group(r'extraChars'))
      end = 1 + extraCount
      if firstChar == r':':
        ao.out(path, lineNr, 0, end, line, r'Old wiki indenting')
        continue
      if firstChar == r';':
        ao.out(path, lineNr, 0, end, line, r'Old wiki definition list')
        continue

    # Old wiki tags:
    matches = rec.finditer(r'''<(?P<close>[/]?)(?P<name>(
      b|i|nowiki|pre|toc|tt
      ))>''', line, re.IGNORECASE | re.VERBOSE)
    for match in matches:
      start = match.start()
      end = match.end()
      closing = match.group(r'close')
      tagName = match.group(r'name')
      if closing:
        tagType = r'close'
      else:
        tagType = r'open'
      ao.out(path, lineNr, start, end, line, r'Old wiki tag %s %s'
        % (tagName, tagType))

    # <<BR>> tags (old and new):
    matches = rec.finditer(r'''
      (?P<open><[<`]*)
      (?P<name>br)
      (?P<close>[>`]*>)
      ''', line, re.IGNORECASE | re.VERBOSE)
    for match in matches:
      start = match.start()
      end = match.end()
      linePart = match.group()
      tagOpen = match.group(r'open')
      tagName = match.group(r'name')
      tagClose = match.group(r'close')
      if (tagOpen == '<') and (tagClose == '>'):
        ao.out(path, lineNr, start, end, line, r'Old wiki linebreak')
        continue
      if (tagOpen == '<<') and (tagClose[0:2] == '>>') and (tagName != 'BR'):
        ao.out(path, lineNr, start, end, line, r'Invalid linebreak')
        continue
    
    # Headlines:
    matches = rec.finditer(r'''^
      (?P<spaceBeforOpen>\s*) # Illegal.
      (?P<openTag>[=]+) # Headline open tag.
      (?P<spaceAfterOpen>\s*) # Required.
      (?P<nIndicator>[\#*]*)\s* # Numbering indicator from old wiki.
      (?P<text>.*?) # Required headline text (non-greedy).
      (?P<spaceBeforClose>\s*) # Required.
      (?P<closeTag>[=]*) # Has to be same as open tag.
      (?P<spaceAfterClose>\s*) # Illegal trailing whitespace.
      $''', line, re.VERBOSE)
    for match in matches:
      linePartPos = match.start()
      linePart = match.group()
      spaceBeforOpen = match.group(r'spaceBeforOpen')
      openTag = match.group(r'openTag')
      openTagStart = match.start(r'openTag')
      openTagEnd = match.end(r'openTag')
      spaceAfterOpen = match.group(r'spaceAfterOpen')
      nIndicator = match.group(r'nIndicator')
      text = match.group(r'text')
      spaceBeforClose = match.group(r'spaceBeforClose')
      closeTag = match.group(r'closeTag')
      spaceAfterClose = match.group(r'spaceAfterClose')
      if spaceBeforOpen:
        end = len(spaceBeforOpen)
        ao.out(path, lineNr, 0, end, line, r'Headline starts with whitespace')
      if len(openTag) > 5:
        start = openTagStart
        end = openTagEnd
        ao.out(path, lineNr, start, end, line, r'Headline of level > 5')
      if not text:
        end = len(line)
        start = openTagEnd - 1
        ao.out(path, lineNr, start, end, line, r'Headline contains no text')
        continue
      else:
        iMatches = rec.finditer(r"[`']{2,}", text)
        for iMatch in iMatches:
          start = match.start(r'text') + iMatch.start()
          end = match.start(r'text') + iMatch.end()
          ao.out(path, lineNr, start, end, line,
            r'Headline text contains markup')
      if not spaceAfterOpen:
        if nIndicator:
          start = match.start(r'nIndicator')
        else:
          start = match.start(r'text')
        ao.out(path, lineNr, start, start + 1, line,
          r'Headline without whitespace after open tag')
      if nIndicator:
        start = match.start(r'nIndicator')
        end = match.end(r'nIndicator')
        ao.out(path, lineNr, start, end, line,
          r'Headline with old numbering indicator')
      if not closeTag:
        ao.out(path, lineNr, len(line) - 1, len(line), line,
          r'Headline without close tag')
        continue # Skip following checks when no close tag present.
      if len(openTag) != len(closeTag):
        start = match.start(r'closeTag')
        end = match.end(r'closeTag')
        ao.out(path, lineNr, start, end, line,
          r'Headline with different length open and close tags')
      if not spaceBeforClose:
        start = match.start(r'closeTag')
        ao.out(path, lineNr, start, start + 1, line,
          r'Headline without whitespace before close tag')
      if spaceAfterClose:
        start = match.start(r'spaceAfterClose')
        end = match.end(r'spaceAfterClose')
        ao.out(path, lineNr, start, end, line, r'Headline ends with whitespace')
        
    # Links:
    matches = rec.finditer(r'''
      (?P<openBrackets>\[[\[`]*) # Link open brackets (2 for valid links).
      (?P<openQuote>"?) # Artifact from old wiki conversion.
      \s*
      (?P<linkUrl>.*?) # Link URL (not greedy).
      \s*
      (?P<closeQuote>"?) # Artifact from old wiki conversion.
      (?P<closeBrackets>[\]`]*\]) # Link open brackets (2 for valid links).
      ''', line, re.IGNORECASE | re.VERBOSE)
    for match in matches:
      start = match.start()
      end = match.end()
      linePart = match.group()
      openBrackets = match.group(r'openBrackets')
      openQuote = match.group(r'openQuote')
      linkUrl = match.group(r'linkUrl')
      closeQuote = match.group(r'closeQuote')
      closeBrackets = match.group(r'closeBrackets')
      if openQuote:
        ao.out(path, lineNr, start, end, line,
          r'Fail-converted unnamed internal link')
        continue
      if (len(openBrackets) == 1) and rec.search(r':', linkUrl):
        ao.out(path, lineNr, start, end, line,
          r'Fail-converted external link')
        continue
    
    # Old wiki uploads:
    matches = rec.finditer(r'(^|\s)(?P<link>upload:\S+)(\s|$)', line, re.I)
    for match in matches:
      start = match.start(r'link')
      end = match.end(r'link')
      ao.out(path, lineNr, start, end, line,
        r'Old wiki upload link')

  file.close()
eFileCount = d.decorateText(str(fileCount), d.textBYellow)
eBlistedCount = d.decorateText(str(blistedCount), d.textBYellow)
if ao.anomalyCount:
  eAnomalyCount = d.decorateText(str(ao.anomalyCount), d.textBYellow)
  eLineCount = d.decorateText(str(ao.lineCount), d.textBYellow)
  ePathCount = d.decorateText(str(ao.pathCount), d.textBYellow)
  o.write(('\nFound %s anomalies in %s lines from %s files'
    + ' (%s scanned, %s excluded):\n')
    % (eAnomalyCount, eLineCount, ePathCount, eFileCount, eBlistedCount))
  anomalyCounts = ao.anomalyCounts
  maxValue = sorted(anomalyCounts.values())[-1]
  format = r'%' + repr(len(repr(maxValue))) + r'i';
  keys = sorted(anomalyCounts.keys())
  for key in keys:
    eCount = d.decorateText(format % (anomalyCounts[key]), d.textBYellow)
    o.write('  %s  %s\n' % (eCount, key))
else:
  o.write('\nFound no anomalies in %i files (%s excluded).\n'
    % (fileCount, eBlistedCount))
