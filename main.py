from core.cli import parse_args
from categories.recon import hostscan


def main():
    args = parse_args()

    if args.category == "recon":
        if args.tool == "hostscan":
            hostscan.run(args)

if __name__ == "__main__":
    main()