import { copyName } from './upload-conflict';

describe('copyName', () => {
    it('numbers a copy beside the file it clashes with', () => {
        expect(copyName('report.pdf', ['report.pdf'])).toBe('report (1).pdf');
    });

    it('keeps counting past copies that already exist', () => {
        expect(copyName('report.pdf', ['report.pdf', 'report (1).pdf', 'report (2).pdf'])).toBe(
            'report (3).pdf'
        );
    });

    it('handles a name with no extension', () => {
        expect(copyName('notes', ['notes'])).toBe('notes (1)');
    });

    it('treats a leading dot as part of the name, not an extension', () => {
        expect(copyName('.env', ['.env'])).toBe('.env (1)');
    });

    it('keeps every dot but the last', () => {
        expect(copyName('archive.tar.gz', ['archive.tar.gz'])).toBe('archive.tar (1).gz');
    });

    it('returns the first free number when the clash list has gaps', () => {
        expect(copyName('a.txt', ['a.txt', 'a (2).txt'])).toBe('a (1).txt');
    });
});
