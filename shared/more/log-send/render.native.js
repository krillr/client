// @flow

import React, {Component} from 'react'
import {Box, Text, Button} from '../../common-adapters'
import {globalStyles} from '../../styles/style-guide'

import {Linking, Clipboard} from 'react-native'

import type {Props} from './render'

type State = {
  copiedToClipboard?: ?boolean
}

export default class Render extends Component<void, Props, State> {
  state: State;

  _copyToClipboard () {
    Clipboard.setString(this.props.logSendId || '')
    this.setState({copiedToClipboard: true})
  }

  render () {
    const onSubmitIssue = () => {
      Linking.openURL(`https://github.com/keybase/client/issues/new?body=[write%20something%20useful%20and%20descriptive%20here]%0A%0Amy%20log%20id:%20${this.props.logSendId}`)
    }

    if (!this.props.logSendId) {
      return (
        <Box style={stylesContainer}>
          <Text type='Body'>Send a log Send?</Text>
          <Text type='Body' style={stylesInfoText}>This command will send recent keybase log entries to keybase.io for debugging purposes only.  These logs don’t include your private keys or encrypted data, but they will include filenames and other metadata keybase normally can’t read, for debugging purposes.</Text>
          <Button type='Primary' label='Send a Log!' onClick={this.props.onLogSend} />
        </Box>
      )
    } else {
      return (
        <Box style={stylesContainer}>
          <Text type='Body'>Your log id is:</Text>
          <Text type='Terminal'
            onClick={() => this._copyToClipboard()}>
            {this.props.logSendId} (tap to copy)
          </Text>
          {!!this.state.copiedToClipboard && <Text type='Body'>Copied to clipboard!</Text>}

          <Text type='Body'>Send us the log id along with your problem in this github issue:</Text>
          <Button type='Primary' label='File a github issue:' onClick={onSubmitIssue} />
        </Box>
      )
    }
  }
}

const stylesContainer = {
  ...globalStyles.flexBoxColumn,
  margin: 20,
  alignItems: 'center',
  justifyContent: 'space-between'
}

const stylesInfoText = {
  marginTop: 20
}