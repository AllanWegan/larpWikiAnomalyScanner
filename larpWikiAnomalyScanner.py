#!/usr/bin/env python3

import re
import glob
import os
import platform
import sys
import unicodedata
import urllib.parse
import codecs

baseDir = os.path.dirname(__file__)

sourceDir = os.path.join(baseDir, 'backup')
blacklist = (
    'HilfeZurCreoleSyntax.txt',
)

class AnomalyFormatter:
    """
    Formats found anomalies and buffers the resuklting text.
    The text buffer is returned and erased by getText().
    Also counts found anomalies.
    """
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
    lastPath = ''
    lastLineNr = 0

    def __init__(self, textEscaper, textDecorator):
        self._buffer = []
        self._escaper = textEscaper
        self._decorator = textDecorator

    def out(self, path, lineNr, startColumn, endColumn, line, anomaly):
        b = self._buffer
        e = self._escaper
        d = self._decorator
        q = self.qoute
        if self.lastPath != path:
            self.lastPath = path
            self.pathCount += 1
            ePath = d.decorateText(e.escape(path), d.textBCyan)
            pageName = os.path.basename(path).replace(' - ', '/')
            if pageName[-4:] == '.txt':
                pageName = pageName[0:-4]
            url = 'https://larpwiki.de/' + urllib.parse.quote(pageName)
            eUrl = d.decorateText(url, d.textWhite)
            b.extend(('\n', ePath, ':\n'))
            b.extend(('  ', eUrl, '\n'))
        if self.lastLineNr != lineNr:
            if self.lastLineNr != lineNr:
                self.lineCount += 1
                self.lastLineNr = lineNr
            eLineNr = d.decorateText(str(lineNr + 1), d.textBYellow)
            b.extend(('  Line ', eLineNr, ':\n'))
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
            after = ''
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
        b.extend(('    Column ', eColumn, ', anomaly ', q, anomaly, q, ':\n'))
        b.extend(('      ', sol, q, before, part, after, q, eol, '\n'))

    def getText(self):
        text = ''.join(self._buffer)
        self._buffer = []
        return text

class AnsiTextDecorator:
    """
    Colorizes output for ANSI terminals
    """
    textBlack = '30'
    textRed = '31'
    textGreen = '32'
    textYellow = '33'
    textBlue = '34'
    textMagenta = '35'
    textCyan = '36'
    textGrey = '37'
    textBGrey = '30;1'
    textBRed = '31;1'
    textBGreen = '32;1'
    textBYellow = '33;1'
    textBBlue = '34;1'
    textBMagenta = '35;1'
    textBCyan = '36;1'
    textWhite = '37;1'
    textBold = '1'
    textItalic = '3'
    textUnderline = '4'
    backgroundBlack = '40'
    backgroundRed = '41'
    backgroundGreen = '42'
    backgroundYellow = '43'
    backgroundBlue = '44'
    backgroundMagenta = '45'
    backgroundCyan = '46'
    backgroundGrey = '47'

    def decorateText(self, text, *codes):
        if not len(codes):
            return text
        codesStr = ''.join(('\x1B[' + code + 'm' for code in codes))
        return '{0}{1}\x1B[0m'.format(codesStr, text)

class dummyTextDecorator(AnsiTextDecorator):

    def decorateText(self, text, *codes):
        return text

class TextEscaper:
    """
    Escapes non-printable code points except space (0x20).
    """
    def escape(self, text):
        return repr(text)[1:-1].replace('"', r'\"')

    def escapeLimitRight(self, text, maxLength):
        if maxLength <= 0:
            return '', 0
        text = text[:maxLength]
        textEsc = self.escape(text)
        while len(textEsc) > maxLength:
            text = text[0:-1]
            textEsc = self.escape(text)
        return textEsc, len(text)
  
    def escapeLimitLeft(self, text, maxLength):
        if maxLength <= 0:
            return '', 0
        text = text[-maxLength:]
        textEsc = self.escape(text)
        while len(textEsc) > maxLength:
            text = text[1:]
            textEsc = self.escape(text)
        return textEsc, len(text)

_detectSmilieRe = re.compile(r'''(?:^|(?<=\s))
[:;,8B][-~]?[)}\]|({[pPD][=\#]?
(?:\s|$)''', re.VERBOSE)
def detectSmilie(line, offset):
    """
    Detects simple western LTR ASCII smilies like ";~P="

    A smilie starts with a symbol for the eyes, followed by an optional symbol
    for the nose and a symbol for the mouth.
    A symbol for the beard may follow.
    The smilie has to begin and end at the start/end of line or after/before
    whitespace.
    """
    return _detectSmilieRe.match(line, offset) is not None

def checkForInvalidCodePoints(escaper, outputter, path, lineNr, line):
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
        if cp == '�':
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
            cpName = unicodedata.name(cp, 'unnamed')
            if unexpectedMark:
                suffix = ' not preceded by a letter'
            else:
                suffix = ''
            msg = 'Unicode {0} ({1}, category {2}){3}'
            msg = msg.format(escaper.escape(cp), cpName, cpCat, suffix)
            outputter.out(path, lineNr, cpIndex, cpIndex + 1, line, msg)

_checkForUseModListRe = re.compile(r'(\*|#(\*|#([*#])))[*#]*')
def checkForUseModList(outputter, path, lineNr, line, isDirective, isComment):
    match = _checkForUseModListRe.match(line)
    if match:
        isDirective, isComment = False, False
        start = match.start()
        end = match.end()
        outputter.out(path, lineNr, start, end, line, 'UseMod list')
    return isDirective, isComment

_checkForNonCommentAfterRedirectRe = re.compile(r'\s*(\S.*?)\s*$')
def detectNonCommentAfterRedirect(outputter, path, lineNr, line):
    match = _checkForNonCommentAfterRedirectRe.match(line)
    if match:
        start = match.start(1)
        end = match.end(1)
        msg = 'Non-empty non-comment line after valid redirect'
        outputter.out(path, lineNr, start, end, line, msg)
        return True
    return False

_detectRedirect = re.compile(r'#REDIRECT(\s*)(?P<name>.*)')
def detectRedirect(outputter, path, lineNr, line, firstDirectiveLine
, validRedirectPresent):
    match = _detectRedirect.match(line)
    if match:
        if firstDirectiveLine:
            name = match.group('name')
            if not name:
                msg = 'Redirect without target'
                outputter.out(path, lineNr, 0, len(line), line, msg)
            else:
                validRedirectPresent = True
        else:
            msg = 'Redirect in non-first line'
            outputter.out(path, lineNr, 0, len(line), line, msg)
        return validRedirectPresent, True
    return validRedirectPresent, False

def detectUseModIndent(outputter, path, lineNr, line):
    if line[0:1] != ':' or detectSmilie(line, 0):
        return False
    end = len(line) - len(line.lstrip(';'))
    outputter.out(path, lineNr, 0, end, line, 'UseMod indentation')
    return True

def detectUseModDefinitionList(outputter, path, lineNr, line):
    if line[0:1] != ';' or detectSmilie(line, 0):
        return False
    outputter.out(path, lineNr, 0, 1, line, 'UseMod definition list')
    return True

_detectUseModTagsRe = re.compile(r'''<(?P<close>[/]?)
(?P<name>(b|i|nowiki|pre|toc|tt))
>''', re.IGNORECASE | re.VERBOSE)
def detectUseModTags(outputter, path, lineNr, line):
    matches = _detectUseModTagsRe.finditer(line)
    for match in matches:
        start = match.start()
        end = match.end()
        closing = match.group('close')
        tagName = match.group('name').lower()
        tagType = 'close' if closing else 'open'
        msg = 'UseMod tag {0} {1}'.format(tagName, tagType)
        outputter.out(path, lineNr, start, end, line, msg)
    return False

_checkBrTagsRe = re.compile(r'''
(?P<open><[<`]*)
(?P<name>br)
(?P<close>[>`]*>)
''', re.IGNORECASE | re.VERBOSE)
def checkBrTags(outputter, path, lineNr, line):
    """
    UseMod forced linebreak: <br>
    MoinMoin forced linebreak: <<BR>>
    """
    matches = _checkBrTagsRe.finditer(line)
    for match in matches:
        start = match.start()
        end = match.end()
        tagOpen = match.group('open')
        tagName = match.group('name')
        tagClose = match.group('close')
        if (tagOpen == '<') and (tagClose == '>'):
            msg = 'UseMod forced linebreak'
            outputter.out(path, lineNr, start, end, line, msg)
            return True
        if ((tagOpen == '<<') and (tagClose[0:2] == '>>')
        and (tagName != 'BR')):
            msg = 'Invalid MoinMoin forced linebreak'
            outputter.out(path, lineNr, start, end, line, msg)
            return True
    return False

_checkHeadlinesRe = re.compile(r'''
(?P<spaceBeforOpen>\s*) # Illegal.
(?P<openTag>[=]+) # Headline open tag.
(?P<spaceAfterOpen>\s*) # Required.
(?P<nIndicator>[\#*]*)\s* # Numbering from old wiki.
(?P<text>.*?) # Required headline text (non-greedy).
(?P<spaceBeforClose>\s*) # Required.
(?P<closeTag>[=]*) # Has to be same as open tag.
(?P<spaceAfterClose>\s*) # Illegal trailing whitespace.
$''', re.VERBOSE)
def checkHeadlines(outputter, path, lineNr, line):
    match = _checkHeadlinesRe.match(line)
    if match is None:
        return False
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
        msg = 'Headline after whitespace'
        outputter.out(path, lineNr, 0, end, line, msg)
    if len(openTag) > 5:
        start = openTagStart
        end = openTagEnd
        msg = 'Headline of level > 5'
        outputter.out(path, lineNr, start, end, line, msg)
    if text:
        iMatches = re.finditer(r"[`']{2,}", text)
        for iMatch in iMatches:
            start = match.start('text') + iMatch.start()
            end = match.start('text') + iMatch.end()
            msg = 'Headline contains markup'
            outputter.out(path, lineNr, start, end, line, msg)
    else:
        end = len(line)
        start = openTagEnd - 1
        msg = 'Headline contains no text'
        outputter.out(path, lineNr, start, end, line, msg)
        return True
    if not spaceAfterOpen:
        if nIndicator:
            start = match.start('nIndicator')
        else:
            start = match.start('text')
        msg = 'Headline without whitespace after open tag'
        outputter.out(path, lineNr, start, start + 1, line, msg)
    if nIndicator:
        start = match.start('nIndicator')
        end = match.end('nIndicator')
        msg = 'Headline with UseMod numbering indicator'
        outputter.out(path, lineNr, start, end, line, msg)
    if closeTag:
        if len(openTag) != len(closeTag):
            start = match.start('closeTag')
            end = match.end('closeTag')
            msg = ('Headline with different length open and close'
            + ' tags')
            outputter.out(path, lineNr, start, end, line, msg)
        if not spaceBeforClose:
            start = match.start('closeTag')
            msg = 'Headline without whitespace before close tag'
            outputter.out(path, lineNr, start, start + 1, line, msg)
        if spaceAfterClose:
            start = match.start('spaceAfterClose')
            end = match.end('spaceAfterClose')
            msg = 'Headline ends with whitespace'
            outputter.out(path, lineNr, start, end, line, msg)
    else:
        msg = 'Headline without close tag'
        outputter.out(path, lineNr, len(line)-1, len(line), line, msg)
        # Skip following checks when no close tag present.
    return True

_checkLinksRe = re.compile(r'''
(?P<openBrackets>\[[\[`]*) # Valid links got 2 brackets
(?P<openQuote>"?) # Artifact from old wiki conversion
\s*
(?P<linkUrl>.*?) # Link URL (not greedy)
\s*
(?P<closeQuote>"?) # Artifact from old wiki conversion
(?P<closeBrackets>[\]`]*\]) # Valid links got 2 brackets
''', re.IGNORECASE | re.VERBOSE)
def checkLinks(outputter, path, lineNr, line):
    matches = _checkLinksRe.finditer(line)
    for match in matches:
        start = match.start()
        end = match.end()
        openBrackets = match.group('openBrackets')
        openQuote = match.group('openQuote')
        linkUrl = match.group('linkUrl')
        if openQuote:
            msg = 'Fail-converted unnamed internal UseMod link'
            outputter.out(path, lineNr, start, end, line, msg)
            continue
        if (len(openBrackets) == 1) and re.search(r':', linkUrl):
            msg = 'Fail-converted external UseMod link'
            outputter.out(path, lineNr, start, end, line, msg)
            continue
    return False

_detectUseModUploadsRe = re.compile(r'(^|\s)(?P<link>upload:\S+)(\s|$)', re.I)
def detectUseModUploads(outputter, path, lineNr, line):
    matches = _detectUseModUploadsRe.finditer(line)
    for match in matches:
        start = match.start('link')
        end = match.end('link')
        msg = 'UseMod upload link'
        outputter.out(path, lineNr, start, end, line, msg)
    return False

# noinspection PyUnusedLocal
def detectMoinMoinComment(outputter, path, lineNr, line):
    return line.startswith('##')

def checkFile(escaper, outputter, path, checkFuns):

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
            msg = 'UTF-8 invalid byte while decoding line!'
            outputter.out(path, lineNr, cpIndex, cpIndex + 1, lineStr, msg)
            break
    if invalidEncoding:
        return
    lines.append(''.join(line))

    firstDirectiveLine = 1
    validRedirectPresent = False
    for lineNr, line in enumerate(lines):
        isComment = detectMoinMoinComment(outputter, path, lineNr, line)
        isDirective = not isComment and line.startswith('#')

        checkForInvalidCodePoints(escaper, outputter, path, lineNr
        , line)

        isDirective, isComment = checkForUseModList(outputter, path
        , lineNr, line, isDirective, isComment)

        # No further wiki syntax checks for comments:
        if isComment:
            continue

        # Determine first directive line
        if (firstDirectiveLine == lineNr) and isComment:
            firstDirectiveLine += 1

        # Detect extra non-comment markup after valid redirect:
        if validRedirectPresent and not isDirective:
            skipRemaining = detectNonCommentAfterRedirect(outputter, path
            , lineNr, line)
            if skipRemaining:
                continue

        validRedirectPresent, skipRemaining = detectRedirect(outputter, path
        , lineNr, line, firstDirectiveLine, validRedirectPresent)
        if skipRemaining:
            continue

        if isDirective:
            # Skip other directives.
            continue

        for checkFun in checkFuns:
            skipRemaining = checkFun(outputter, path, lineNr, line)
            if skipRemaining:
                continue

def main():
    checkFuns = (
        detectUseModIndent,
        detectUseModDefinitionList,
        detectUseModTags,
        checkBrTags,
        checkHeadlines,
        checkLinks,
        detectUseModUploads,
    )

    o = sys.stdout
    escaper = TextEscaper()
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
    outputter = AnomalyFormatter(escaper, d)
    outputter.maxPartLength = cols - 11
    fileCount = 0
    blistedCount = 0
    try:
        print('Scanning files...', file=o)
        paths = glob.iglob(os.path.join(sourceDir, "*.txt"))
        for path in paths:
            if not os.path.isfile(path):
                continue
            if path in blacklist:
                blistedCount += 1
                continue
            fileCount += 1
            checkFile(escaper, outputter, path, checkFuns)
            text = outputter.getText()
            if len(text) != 0:
                print(text, end='', file=o)

    except KeyboardInterrupt:
        print('', file=o)
        print('Processing interrupted by user!', file=o)

    eFileCount = d.decorateText(str(fileCount), d.textBYellow)
    eBlistedCount = d.decorateText(str(blistedCount), d.textBYellow)
    if outputter.anomalyCount:
        eAnomalyCount = d.decorateText(str(outputter.anomalyCount), d.textBYellow)
        eLineCount = d.decorateText(str(outputter.lineCount), d.textBYellow)
        ePathCount = d.decorateText(str(outputter.pathCount), d.textBYellow)
        msg = ('Found {0} anomalies in {1} lines from {2} files'
        + ' ({3} scanned, {4} excluded):')
        print('', file=o)
        print(msg.format(eAnomalyCount, eLineCount, ePathCount, eFileCount
        , eBlistedCount), file=o)
        anomalyCounts = outputter.anomalyCounts
        maxValue = sorted(anomalyCounts.values())[-1]
        maxValueLen = len(str(maxValue))
        keys = sorted(anomalyCounts.keys())
        for key in keys:
            eCount = '{0:{1}}'.format(anomalyCounts[key], maxValueLen)
            eCount = d.decorateText(eCount, d.textBYellow)
            print('  {0}  {1}'.format(eCount, key), file=o)
    else:
        msg = 'Found no anomalies in {0} files ({1} excluded).'
        print('', file=o)
        print(msg.format(fileCount, eBlistedCount), file=o)

if __name__ == '__main__':
    main()
