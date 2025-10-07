import { logger } from '@altipla/logging'
import { CloudTasksClient } from '@google-cloud/tasks'
import { H3Event, HTTPError } from 'h3'
import ksuid from 'ksuid'
import { OAuth2Client } from 'google-auth-library'

export type QueueName = string & { readonly _: unique symbol }
export function queueName(name: string): QueueName {
  return name as QueueName
}

const ENV_PRODUCTION = process.env.NODE_ENV === 'production'

export type CloudTasksConfig = {
  credentials?: string
  project: string
  location: string
  audience: string
  serviceAccount: string
  base: string
}
export function defineTasksConfig(config: CloudTasksConfig): CloudTasksConfig {
  return config
}

let cachedTasksClient: CloudTasksClient
function initTasksClient(config: CloudTasksConfig) {
  if (!cachedTasksClient) {
    cachedTasksClient = new CloudTasksClient({
      credentials: config.credentials ? JSON.parse(config.credentials) : undefined,
    })
  }
  return cachedTasksClient
}

export async function sendTask(config: CloudTasksConfig, queue: QueueName, url: string, payload: string) {
  const tasksClient = initTasksClient(config)

  let u = new URL(url, config.base)

  if (!ENV_PRODUCTION) {
    logger.debug({
      msg: 'simulate local task',
      url: u.toString(),
      payload,
    })
    void fetch(u.toString(), {
      method: 'POST',
      body: payload,
      headers: {
        'x-cloudtasks-queuename': queue,
        'x-cloudtasks-taskname': ksuid.randomSync().string,
        'x-cloudtasks-taskretrycount': '0',
        authorization: `Bearer local-token`,
      },
    })
    return ksuid.randomSync().string
  }

  const [response] = await tasksClient.createTask({
    parent: tasksClient.queuePath(config.project, config.location, queue),
    task: {
      httpRequest: {
        httpMethod: 'POST',
        url: u.toString(),
        body: Buffer.from(payload).toString('base64'),
        oidcToken: {
          audience: config.audience,
          serviceAccountEmail: config.serviceAccount,
        },
      },
    },
  })
  return response.name
}

type Task = {
  queueName: QueueName
  taskName: string
  retryCount: number
}
const authClient = new OAuth2Client()
export async function verifyTask(event: H3Event, config: CloudTasksConfig): Promise<Task> {
  let authorization = event.req.headers.get('authorization')
  if (!authorization?.startsWith('Bearer ')) {
    throw new HTTPError(`invalid authorization: ${authorization}`, { status: 401 })
  }
  let bearer = authorization.slice(7)

  if (!ENV_PRODUCTION) {
    if (bearer !== 'local-token') {
      throw new HTTPError(`invalid authentication: ${bearer}`, { status: 401 })
    }
    return readTask(event)
  }

  try {
    await authClient.verifyIdToken({
      idToken: bearer,
      audience: config.audience,
    })
  } catch (error) {
    throw new HTTPError('invalid authentication', { status: 401, cause: error })
  }

  return readTask(event)
}

function readTask(event: H3Event): Task {
  return {
    queueName: event.req.headers.get('x-cloudtasks-queuename') as QueueName,
    taskName: event.req.headers.get('x-cloudtasks-taskname')!,
    retryCount: parseInt(event.req.headers.get('x-cloudtasks-taskretrycount')!, 10),
  } satisfies Task
}
