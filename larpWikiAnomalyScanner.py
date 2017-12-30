#!/usr/bin/env python3
#
# Scans all wiki page sources in configured directory and outputs found
# anomalies to stdout in a human readable format.
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
# 2017-12-30 Allan Wegan <allanwegan@allanwegan.de>
#

import re
import glob
import os
import platform
import sys
import unicodedata
import urllib.parse
from io import StringIO
import codecs

baseDir = os.path.dirname(__file__)

sourceDir = os.path.join(baseDir, 'backup')
blacklist = (
    'HilfeZurCreoleSyntax.txt',
)

# Finds all occurences of a regular expression pattern in given :
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
class AnomalyOutputter:

    qoute = '"'
    ellipsis = '…'
    sol = '|'
    eol = '|'
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
            pageName = os.path.basename(path).replace(r' - ', '/')
            if pageName[-4:] == '.txt':
                pageName = pageName[0:-4]
            url = 'https://larpwiki.de/' + urllib.parse.quote(pageName)
            eUrl = d.decorateText(url, d.textWhite)
            o.write('\n{0}:\n  {1}\n'.format(ePath, eUrl))
        if self.lastLineNr != lineNr:
            if self.lastLineNr != lineNr:
                self.lineCount += 1
                self.lastLineNr = lineNr
            eLineNr = d.decorateText(str(lineNr + 1), d.textBYellow)
            o.write('  Line {0}:\n'.format(eLineNr))
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
            mal = min(len(line) - endColumn, int(ml / 2), self.minAfterLength)
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
        msg = '    Column {1}, anomaly {0}{2}{0}:\n'
        o.write(msg.format(q, eColumn, anomaly))
        msg = '      {1}{0}{2}{3}{4}{0}{5}\n'
        o.write(msg.format(q, sol, before, part, after, eol))

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
class TextEscaper:
  
    def escape(self, text):
        if not len(text): return r''
        return repr(text)[1:-1].replace(r'"', r'\"')

    def escapeLimitRight(self, text, maxLength):
        if maxLength <= 0:
            return r'', 0
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
        return buffer.getvalue(), cpCount
  
    def escapeLimitLeft(self, text, maxLength):
        if maxLength <= 0:
            return r'', 0
        cpList = []
        length = 0
        index = len(text)
        while index > 0:
            index -= 1
            cp = self.escape(text[index])
            newLength = length + len(cp)
            if newLength > maxLength:
                break
            cpList.insert(0, cp)
            length = newLength
            if length == maxLength:
                break
        buffer = StringIO()
        for cp in cpList:
            buffer.write(cp)
        return buffer.getvalue(), len(cpList)

def main():
    o = sys.stdout
    e = TextEscaper()
    if o.isatty() and (platform.system() != 'Windows'):
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
    fileCount = 0
    blistedCount = 0
    try:
        o.write('Scanning files...\n')
        paths = glob.iglob(os.path.join(sourceDir, "*.txt"))
        for path in paths:
            if not os.path.isfile(path):
                continue
            if path in blacklist:
                blistedCount += 1
                continue
            fileCount += 1

            # Read file and report broken UTF-8 encoding:
            with open(path, 'rb') as file:
                textBytes = file.read()
            decoder = codecs.getincrementaldecoder('utf-8')()
            lines, line, invalidEncoding = [], [], False
            lastI = len(textBytes) + 1
            for i in range(0, len(textBytes)):
                try:
                    cp = decoder.decode(textBytes[i:i+1], i == lastI)
                    if len(cp) != 0:
                        if cp == '\n':
                            if line[-1:] == ['\r']:
                                del line[-1]
                            lines.append(''.join(line))
                            line = []
                        else:
                            line.append(cp)
                except ValueError:
                    invalidEncoding = True
                    lineNr, cpIndex = len(lines) + 1, len(line)
                    lineStr = ''.join(line)
                    msg = r'UTF-8 invalid byte while decoding line!'
                    ao.out(path, lineNr, cpIndex, cpIndex + 1, lineStr, msg)
                    break
            if invalidEncoding:
                continue
            lines.append(''.join(line))

            firstDirectiveLine = 1
            validRedirectPresent = False
            for lineNr, line in enumerate(lines):
                commentLine = line.startswith('##')
                directiveLine = not commentLine and line.startswith('#')

                # Obscure code points:
                markAllowed = False
                for cpIndex, cp in enumerate(line):
                    anomaly = True
                    unexpectedMark = False
                    cpCat = unicodedata.category(cp)
                    cpCatMain = cpCat[0]

                    # Don't report letters, numbers, punctuation, symbols,
                    # whitespace and some miscategorized whitespace:
                    if cpCatMain in 'LNPSZ' or cp in (
                        '\t',
                        '\xad', # SOFT HYPHEN, category Cf
                        '\u200d', # ZERO WIDTH JOINER, category Cf
                        '\u200e', # LEFT-TO-RIGHT MARK, category Cf
                        None
                    ):
                        anomaly = False

                    # But report REPLACEMENT CHARACTER from category So, because
                    # it most likely is a character set conversion artifact:
                    if cp == r'�':
                        anomaly = True

                    # Don't report marks following letters or other marks:
                    if cpCatMain == 'M':
                        if markAllowed:
                            anomaly = False
                        else:
                            # Not in letter cluster.
                            anomaly, unexpectedMark = True, True
                    elif cpCatMain == 'L':
                        markAllowed = True
                    else:
                        markAllowed = False

                    if anomaly:
                        cpName = unicodedata.name(cp, r'unnamed')
                        if unexpectedMark:
                            suffix = ' not preceded by a letter'
                        else:
                            suffix = ''
                        msg = r'Unicode {0} ({1}, category {2}){3}'
                        msg = msg.format(e.escape(cp), cpName, cpCat, suffix)
                        ao.out(path, lineNr, cpIndex, cpIndex + 1, line, msg)

                # Old-wiki-style lists:
                match = rec.match(r'(\*|#(\*|#(\*|#)))[*#]*', line)
                if match:
                    directiveLine = False
                    commentLine = False
                    start = match.start()
                    end = match.end()
                    ao.out(path, lineNr, start, end, line, 'Old wiki list')

                # No further wiki syntax checks for comments or after valid
                # redirects:
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
                        msg = 'Non-empty non-comment line after valid redirect'
                        ao.out(path, lineNr, start, end, line, msg)
                        continue

                # Detect redirects:
                match = rec.match(r'#REDIRECT(\s*)(?P<name>.*)', line)
                if match:
                    if firstDirectiveLine:
                        name = match.group(r'name')
                        if not name:
                            msg = 'Redirect without target'
                            ao.out(path, lineNr, 0, len(line), line, msg)
                        else:
                            validRedirectPresent = True
                    else:
                        msg = 'Redirect in non-first line'
                        ao.out(path, lineNr, 0, len(line), line, msg)
                    continue

                # Skip other directives:
                if directiveLine:
                    continue

                # Old-wiki-style features dependent on first char of line:
                match = rec.match(r'''^(?P<firstChar>[:;])((?P<extraChars>[:;]*)
                    |($|[^-\(\{\[\|\)\}\]pPD] # Do not match smilies.
                    ))''', line, re.VERBOSE)
                if match:
                    firstChar = match.group(r'firstChar')
                    extraCount = len(match.group(r'extraChars'))
                    end = 1 + extraCount
                    if firstChar == r':':
                        msg = 'Old wiki indenting'
                        ao.out(path, lineNr, 0, end, line, msg)
                        continue
                    if firstChar == r';':
                        msg = 'Old wiki definition list'
                        ao.out(path, lineNr, 0, end, line, msg)
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
                    tagType = 'close' if closing else 'open'
                    msg = 'Old wiki tag {0} {1}'.format(tagName, tagType)
                    ao.out(path, lineNr, start, end, line, msg)

                # <<BR>> tags (old and new):
                matches = rec.finditer(r'''
                    (?P<open><[<`]*)
                    (?P<name>br)
                    (?P<close>[>`]*>)
                    ''', line, re.IGNORECASE | re.VERBOSE)
                for match in matches:
                    start = match.start()
                    end = match.end()
                    tagOpen = match.group('open')
                    tagName = match.group('name')
                    tagClose = match.group('close')
                    if (tagOpen == '<') and (tagClose == '>'):
                        msg = 'Old wiki linebreak'
                        ao.out(path, lineNr, start, end, line, msg)
                        continue
                    if ((tagOpen == '<<') and (tagClose[0:2] == '>>')
                    and (tagName != 'BR')):
                        msg = 'Invalid linebreak'
                        ao.out(path, lineNr, start, end, line, msg)
                        continue

                # Headlines:
                matches = rec.finditer(r'''^
                    (?P<spaceBeforOpen>\s*) # Illegal.
                    (?P<openTag>[=]+) # Headline open tag.
                    (?P<spaceAfterOpen>\s*) # Required.
                    (?P<nIndicator>[\#*]*)\s* # Numbering from old wiki.
                    (?P<text>.*?) # Required headline text (non-greedy).
                    (?P<spaceBeforClose>\s*) # Required.
                    (?P<closeTag>[=]*) # Has to be same as open tag.
                    (?P<spaceAfterClose>\s*) # Illegal trailing whitespace.
                    $''', line, re.VERBOSE)
                for match in matches:
                    spaceBeforOpen = match.group('spaceBeforOpen')
                    openTag = match.group('openTag')
                    openTagStart = match.start('openTag')
                    openTagEnd = match.end('openTag')
                    spaceAfterOpen = match.group('spaceAfterOpen')
                    nIndicator = match.group('nIndicator')
                    text = match.group('text')
                    spaceBeforClose = match.group('spaceBeforClose')
                    closeTag = match.group('closeTag')
                    spaceAfterClose = match.group('spaceAfterClose')
                    if spaceBeforOpen:
                        end = len(spaceBeforOpen)
                        msg = 'Headline starts with whitespace'
                        ao.out(path, lineNr, 0, end, line, msg)
                    if len(openTag) > 5:
                        start = openTagStart
                        end = openTagEnd
                        msg = 'Headline of level > 5'
                        ao.out(path, lineNr, start, end, line, msg)
                    if text:
                        iMatches = rec.finditer(r"[`']{2,}", text)
                        for iMatch in iMatches:
                            start = match.start('text') + iMatch.start()
                            end = match.start('text') + iMatch.end()
                            msg = 'Headline text contains markup'
                            ao.out(path, lineNr, start, end, line, msg)
                    else:
                        end = len(line)
                        start = openTagEnd - 1
                        msg = 'Headline contains no text'
                        ao.out(path, lineNr, start, end, line, msg)
                        continue
                    if not spaceAfterOpen:
                        if nIndicator:
                            start = match.start('nIndicator')
                        else:
                            start = match.start('text')
                        msg = 'Headline without whitespace after open tag'
                        ao.out(path, lineNr, start, start + 1, line, msg)
                    if nIndicator:
                        start = match.start('nIndicator')
                        end = match.end('nIndicator')
                        msg = 'Headline with old numbering indicator'
                        ao.out(path, lineNr, start, end, line, msg)
                    if not closeTag:
                        msg = 'Headline without close tag'
                        ao.out(path, lineNr, len(line)-1, len(line), line, msg)
                        # Skip following checks when no close tag present.
                        continue
                    if len(openTag) != len(closeTag):
                        start = match.start('closeTag')
                        end = match.end('closeTag')
                        msg = ('Headline with different length open and close'
                        + ' tags')
                        ao.out(path, lineNr, start, end, line, msg)
                    if not spaceBeforClose:
                        start = match.start('closeTag')
                        msg = 'Headline without whitespace before close tag'
                        ao.out(path, lineNr, start, start + 1, line, msg)
                    if spaceAfterClose:
                        start = match.start('spaceAfterClose')
                        end = match.end('spaceAfterClose')
                        msg = 'Headline ends with whitespace'
                        ao.out(path, lineNr, start, end, line, msg)

                # Links:
                matches = rec.finditer(r'''
                    (?P<openBrackets>\[[\[`]*) # Valid links got 2 brackets
                    (?P<openQuote>"?) # Artifact from old wiki conversion
                    \s*
                    (?P<linkUrl>.*?) # Link URL (not greedy)
                    \s*
                    (?P<closeQuote>"?) # Artifact from old wiki conversion
                    (?P<closeBrackets>[\]`]*\]) # Valid links got 2 brackets
                    ''', line, re.IGNORECASE | re.VERBOSE)
                for match in matches:
                    start = match.start()
                    end = match.end()
                    openBrackets = match.group('openBrackets')
                    openQuote = match.group('openQuote')
                    linkUrl = match.group('linkUrl')
                    if openQuote:
                        msg = 'Fail-converted unnamed internal link'
                        ao.out(path, lineNr, start, end, line, msg)
                        continue
                    if (len(openBrackets) == 1) and rec.search(r':', linkUrl):
                        msg = 'Fail-converted external link'
                        ao.out(path, lineNr, start, end, line, msg)
                        continue

                # Old wiki uploads:
                reStr = r'(^|\s)(?P<link>upload:\S+)(\s|$)'
                matches = rec.finditer(reStr, line, re.I)
                for match in matches:
                    start = match.start('link')
                    end = match.end('link')
                    msg = 'Old wiki upload link'
                    ao.out(path, lineNr, start, end, line, msg)

    except KeyboardInterrupt:
        o.write('\nProcessing interrupted by user!\n')

    eFileCount = d.decorateText(str(fileCount), d.textBYellow)
    eBlistedCount = d.decorateText(str(blistedCount), d.textBYellow)
    if ao.anomalyCount:
        eAnomalyCount = d.decorateText(str(ao.anomalyCount), d.textBYellow)
        eLineCount = d.decorateText(str(ao.lineCount), d.textBYellow)
        ePathCount = d.decorateText(str(ao.pathCount), d.textBYellow)
        msg = ('\nFound {0} anomalies in {1} lines from {2} files'
        + ' ({3} scanned, {4} excluded):\n')
        o.write(msg.format(eAnomalyCount, eLineCount, ePathCount, eFileCount
        , eBlistedCount))
        anomalyCounts = ao.anomalyCounts
        maxValue = sorted(anomalyCounts.values())[-1]
        maxValueLen = len(str(maxValue))
        keys = sorted(anomalyCounts.keys())
        for key in keys:
            eCount = '{0:{1}}'.format(anomalyCounts[key], maxValueLen)
            eCount = d.decorateText(eCount, d.textBYellow)
            o.write('  {0}  {1}\n'.format(eCount, key))
    else:
        msg = '\nFound no anomalies in {0} files ({1} excluded).\n'
        o.write(msg.format(fileCount, eBlistedCount))

if __name__ == '__main__':
    main()
