from enum import StrEnum
from pathlib import Path

from engine.converter import log_entries_from, Log


class AnalyzerMethods(StrEnum):
    mfip = 'mfip'
    lfip = 'lfip'
    eps = 'eps'
    bts = 'bts'


class Analyzer:
    def __init__(self, input: Path, options: dict):
        self.input = input
        self.options = options
        self.collecting_methods = []
        self.analyzing_methods = []

        self.collected_ip_frequency = {}
        self.collected_events_frequency = {
            'earliest_timestamp': None,
            'latest_timestamp': None,
            'events_number': 0
        }
        self.collected_bytes_amount = 0

        self.result = {}

    def __choose_needed_data_collectors(self):
        if self.options.get(AnalyzerMethods.mfip) or self.options.get(AnalyzerMethods.lfip):
            self.collecting_methods.append(self.__collect_ip_frequency)

        if self.options.get(AnalyzerMethods.eps):
            self.collecting_methods.append(self.__collect_events_frequency)

        if self.options.get(AnalyzerMethods.bts):
            self.collecting_methods.append(self.__collect_exchanged_bytes_amount)

    def __choose_needed_analyzing_methods(self):
        if self.options.get(AnalyzerMethods.mfip):
            self.analyzing_methods.append(self.__analyze_mfip)

        if self.options.get(AnalyzerMethods.lfip):
            self.analyzing_methods.append(self.__analyze_lfip)

        if self.options.get(AnalyzerMethods.eps):
            self.analyzing_methods.append(self.__analyze_eps)

        if self.options.get(AnalyzerMethods.bts):
            self.analyzing_methods.append(self.__analyze_bts)

    def __collect_ip_frequency(self, log_entry: Log):
        client_ip = log_entry.client_ip
        destination_ip = log_entry.destination_ip

        if client_ip not in self.collected_ip_frequency:
            self.collected_ip_frequency[client_ip] = 0

        if destination_ip not in self.collected_ip_frequency:
            self.collected_ip_frequency[destination_ip] = 0

        self.collected_ip_frequency[client_ip] += 1
        self.collected_ip_frequency[destination_ip] += 1

    def __collect_events_frequency(self, log_entry: Log):
        timestamp = log_entry.timestamp
        if (
            self.collected_events_frequency['earliest_timestamp'] is None or
            self.collected_events_frequency['earliest_timestamp'] > timestamp
        ):
            self.collected_events_frequency['earliest_timestamp'] = timestamp

        if (
            self.collected_events_frequency['latest_timestamp'] is None or
            self.collected_events_frequency['latest_timestamp'] < timestamp
        ):
            self.collected_events_frequency['latest_timestamp'] = timestamp

        self.collected_events_frequency['events_number'] += 1

    def __collect_exchanged_bytes_amount(self, log_entry: Log):
        self.collected_bytes_amount += int(log_entry.header_size)

    def __analyze_mfip(self):
        greatest_frequency = 0
        most_frequent_ip = None

        for ip, frequency in self.collected_ip_frequency.items():
            if 'none' not in str(ip).lower() and frequency > greatest_frequency:
                greatest_frequency = frequency
                most_frequent_ip = ip

        self.result[AnalyzerMethods.mfip] = most_frequent_ip

    def __analyze_lfip(self):
        lowest_frequency = None
        least_frequent_ip = None

        for ip, frequency in self.collected_ip_frequency.items():
            if lowest_frequency is None:
                lowest_frequency = frequency

            if 'none' not in str(ip).lower() and frequency < lowest_frequency:
                lowest_frequency = frequency
                least_frequent_ip = ip

        self.result[AnalyzerMethods.lfip] = least_frequent_ip

    def __analyze_eps(self):
        self.result[AnalyzerMethods.eps] = (
            self.collected_events_frequency['events_number'] /
            (
                float(self.collected_events_frequency['latest_timestamp']) -
                float(self.collected_events_frequency['earliest_timestamp'])
            )
        )

    def __analyze_bts(self):
        self.result[AnalyzerMethods.bts] = self.collected_bytes_amount

    def analyze(self):
        self.__choose_needed_data_collectors()
        self.__choose_needed_analyzing_methods()

        for log_entry in log_entries_from(self.input):
            for collecting_method in self.collecting_methods:
                collecting_method(log_entry)

        for analyzing_method in self.analyzing_methods:
            analyzing_method()

        return self.result
