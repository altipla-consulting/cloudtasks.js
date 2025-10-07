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
  /** JSON credentials for the service account. */
  credentials?: string

  /** Google Cloud project ID. */
  project: string

  /** Location of the queue. Example: `us-central1` or `europe-west1`	. */
  location: string

  /** Audience of the token for the OIDC authentication. Most of the time it will be the URL of the service. */
  audience: string

  /** The service account email to use for the OIDC authentication. */
  serviceAccount: string

  /** Base URL of the service to concatenate with the URL of the task. */
  baseURL: string

  /** Force the environment to be production or development. By default it will be the value of the NODE_ENV environment variable. */
  forcedEnvironment?: 'production' | 'development'
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

/**
 * Send a task to a queue.
 * @param config - Configuration of the library.
 * @param queue - Name of the queue to send the task to.
 * @param url - Target URL of the task to send.
 * @param payload - Payload of the task to send.
 * @returns Generated name of the task.
 */
export async function sendTask(config: CloudTasksConfig, queue: QueueName, url: string, payload: string) {
  const tasksClient = initTasksClient(config)

  let u = new URL(url, config.baseURL)

  if (!ENV_PRODUCTION && config.forcedEnvironment !== 'production') {
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

/**
 * Verify the authentication of a received task.
 * @param config Configuration of the library.
 * @param event H3 event to verify the request.
 * @returns Verified task content.
 */
export async function verifyTaskH3(config: CloudTasksConfig, event: H3Event): Promise<Task> {
  let authorization = event.req.headers.get('authorization')
  if (!authorization?.startsWith('Bearer ')) {
    throw new HTTPError(`invalid authorization: ${authorization}`, { status: 401 })
  }
  let bearer = authorization.slice(7)

  if (!ENV_PRODUCTION && config.forcedEnvironment !== 'production') {
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
