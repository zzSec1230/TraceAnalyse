import argparse
import os

from src.AnalyseEngine import AnalyseEngine

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process input and output files.')
    parser.add_argument('-i', '--input', type=str,default='/Users/bytedance/ios_reverse/TraceAnalyse/test/trace.log', help='Input file path')
    parser.add_argument('-o', '--output', type=str,default='/Users/bytedance/ios_reverse/TraceAnalyse/test/trace_output.log', help='Output file path')

    args = parser.parse_args()
    #
    # print(f'Input file: {args.input}')
    # print(f'Output file: {args.output}')
    traceEngine = AnalyseEngine()
    traceSnapshot = traceEngine.LoadDumpFile(args.input)
    if os.path.exists(args.output):
        os.remove(args.output)

    traceEngine.show(traceSnapshot,args.output)
