# -*- coding: binary -*-

#
# A helper module for using and referencing comming user agent strings.
#
module Rex::UserAgent

  #
  # Taken from https://www.whatismybrowser.com/guides/the-latest-user-agent/
  #
  COMMON_AGENTS = [
      # Chrome
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.81 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.81 Safari/537.36',

      # Edge
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.81 Safari/537.36 Edg/97.0.1072.69',

      # Safari
      'Mozilla/5.0 (iPad; CPU OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15',

      # Firefox
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.2; rv:97.0) Gecko/20100101 Firefox/97.0',
  ]

  #
  # A randomly-selected agent that will be consistent for the duration of metasploit running
  #
  def self.session_agent
    if @@session_agent
      @@session_agent
    else
      @@session_agent = self.random
    end
  end

  @@session_agent = nil

  #
  # Pick a random agent from the common agent list.
  #
  def self.random
    COMMON_AGENTS.sample
  end

  #
  # Choose the agent with the shortest string (for use in payloads)
  #
  def self.shortest
    @@shortest_agent ||= COMMON_AGENTS.min { |a, b| a.size <=> b.size }
  end

  #
  # Choose the most frequent user agent
  #
  def self.most_common
    COMMON_AGENTS[0]
  end

end

